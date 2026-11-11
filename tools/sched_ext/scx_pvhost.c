/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA Corporation.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <dirent.h>
#include <libgen.h>
#include <limits.h>
#include <pwd.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/inotify.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <linux/magic.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_pv.h"
#include "scx_pv_topo.h"
#include "scx_pvhost.bpf.skel.h"

const char help_fmt[] =
"Host half of a paravirt scheduler pair, run scx_pvguest in the guests.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"A VM is registered when its VMM, QEMU or Firecracker, maps a file in DIR as\n"
"the backend of its virtio-pmem or NVDIMM device, e.g. with QEMU on arm64:\n"
"\n"
"  -machine nvdimm=on -m 2G,slots=2,maxmem=4G\n"
"  -object memory-backend-file,id=scxpv,mem-path=DIR/NAME,size=16M,share=on\n"
"  -device nvdimm,memdev=scxpv            (or virtio-pmem-pci on x86)\n"
"\n"
"or with Firecracker, on a 16M file created beforehand:\n"
"\n"
"  \"pmem\": [{\"id\": \"scxpv\", \"path_on_host\": \"DIR/NAME\"}]\n"
"\n"
"Usage: %s [-d DIR] [-u USER] [-p PCPUS] [-C CPUS] [-s SLICE_US] [-T] [-W] [-A] [-v]\n"
"\n"
"  -d DIR        Directory of the guests' shared memory files, on tmpfs or\n"
"                hugetlbfs (default: /run/scx-pv)\n"
"  -u USER       Give DIR to USER, name or uid, so that its VMMs can create\n"
"                the files without root\n"
"  -p PCPUS      Host CPUs shared by the guests (default: all online CPUs,\n"
"                or the CPUs of -C)\n"
"  -C CPUS       Host CPUs the guests run on (e.g. 8-15,184-191): the threads\n"
"                of their VMM are confined there, and only these count as\n"
"                idle host CPUs\n"
"  -s SLICE_US   Slice of every task in microseconds (default: 5000)\n"
"  -T            Fairness per task only: a guest without the guest scheduler\n"
"                isn't held to its share of the host CPUs\n"
"  -W            SMT: a wholly idle core wins over an idle thread of a busy\n"
"                core, also in another LLC\n"
"  -A            SMT: take the first thread of an idle core\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

/* How long a new file in the directory may wait for a VMM to map it */
#define PENDING_TIMEOUT_S	30

enum slot_state {
	SLOT_FREE,
	SLOT_PENDING,		/* file seen, waiting for its VMM */
	SLOT_LIVE,		/* imported into the arena */
};

struct guest {
	enum slot_state state;
	char name[NAME_MAX + 1];	/* file in the directory */
	time_t pending_since;
	int fd;
	dev_t dev;
	ino_t ino;
	void *map;		/* PV_PAGES pages of the file at PV_DAX_OFF */
	pid_t vmm_pid;
	int pidfd;		/* of the VMM process, -1 to poll it instead */
	__u32 nr_threads;	/* vCPU threads added to vcpu_threads */
	__u64 nr_preempted;
};

static bool verbose;
static cpu_set_t pool;
static int nr_pool;
static volatile int exit_req;
static struct guest guests[PV_MAX_GUESTS];
static const char *dir_path = "/run/scx-pv";
static const char *dir_user;
static int dir_fd = -1;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int sig)
{
	exit_req = 1;
}

static struct guest *find_guest(const char *name)
{
	int i;

	for (i = 0; i < PV_MAX_GUESTS; i++)
		if (guests[i].state != SLOT_FREE && !strcmp(guests[i].name, name))
			return &guests[i];
	return NULL;
}

/* A file showed up or was opened: wait for a VMM to map it */
static void add_pending(const char *name)
{
	int i;

	if (name[0] == '.' || find_guest(name))
		return;
	for (i = 0; i < PV_MAX_GUESTS; i++) {
		struct guest *g = &guests[i];

		if (g->state != SLOT_FREE)
			continue;
		memset(g, 0, sizeof(*g));
		snprintf(g->name, sizeof(g->name), "%s", name);
		g->state = SLOT_PENDING;
		g->pending_since = time(NULL);
		g->fd = -1;
		g->pidfd = -1;
		return;
	}
	fprintf(stderr, "%s: no free slot, up to %d guests\n", name, PV_MAX_GUESTS);
}

static void drop_pending(struct guest *g)
{
	if (g->fd >= 0)
		close(g->fd);
	g->state = SLOT_FREE;
}

/*
 * Open the file without following symlinks, and only accept a regular file
 * on tmpfs or hugetlbfs, the only files bpf_arena_import_memfd() takes.
 */
static int open_backing(struct guest *g)
{
	struct statfs sfs;
	struct stat st;
	int fd;

	fd = openat(dir_fd, g->name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) || !S_ISREG(st.st_mode) || fstatfs(fd, &sfs) ||
	    (sfs.f_type != TMPFS_MAGIC && sfs.f_type != HUGETLBFS_MAGIC)) {
		close(fd);
		return -EINVAL;
	}
	g->fd = fd;
	g->dev = st.st_dev;
	g->ino = st.st_ino;
	return 0;
}

/* Does @pid map the file of @g? */
static bool maps_file(pid_t pid, struct guest *g)
{
	unsigned int maj, min;
	unsigned long long ino;
	char path[64], line[512];
	bool found = false;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	f = fopen(path, "r");
	if (!f)
		return false;
	while (!found && fgets(line, sizeof(line), f))
		found = sscanf(line, "%*s %*s %*s %x:%x %llu", &maj, &min, &ino) == 3 &&
			ino == g->ino && makedev(maj, min) == g->dev;
	fclose(f);
	return found;
}

/* Does @pid hold a KVM VM file descriptor? */
static bool has_kvm_vm(pid_t pid)
{
	char path[PATH_MAX], link[64];
	struct dirent *de;
	bool found = false;
	ssize_t len;
	DIR *dir;

	snprintf(path, sizeof(path), "/proc/%d/fd", pid);
	dir = opendir(path);
	if (!dir)
		return false;
	while (!found && (de = readdir(dir))) {
		snprintf(path, sizeof(path), "/proc/%d/fd/%s", pid, de->d_name);
		len = readlink(path, link, sizeof(link) - 1);
		if (len <= 0)
			continue;
		link[len] = '\0';
		found = !strcmp(link, "anon_inode:kvm-vm");
	}
	closedir(dir);
	return found;
}

/*
 * The VMM of @g: the process mapping its file that runs a KVM VM, such as
 * QEMU or Firecracker.
 * Other processes may map it too, such as a virtiofsd or another
 * vhost-user backend, which maps all the guest's memory.
 */
static pid_t find_vmm(struct guest *g)
{
	struct dirent *de;
	pid_t pid, found = 0;
	DIR *dir;

	dir = opendir("/proc");
	if (!dir)
		return 0;
	while (!found && (de = readdir(dir))) {
		pid = atoi(de->d_name);
		if (pid > 0 && pid != getpid() && maps_file(pid, g) && has_kvm_vm(pid))
			found = pid;
	}
	closedir(dir);
	return found;
}

static int run_prog(struct bpf_program *prog)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	return bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
}

/* Forget the vCPU threads of slot @id: tids get reused */
static void forget_vcpu_threads(struct scx_pvhost *skel, int id)
{
	struct { __u32 guest, vcpu; } val;
	int map = bpf_map__fd(skel->maps.vcpu_threads);
	__u32 key, next, *prev = NULL;

	while (!bpf_map_get_next_key(map, prev, &next)) {
		key = next;
		if (!bpf_map_lookup_elem(map, &key, &val) && val.guest == id) {
			bpf_map_delete_elem(map, &key);
			continue;
		}
		prev = &key;
	}
}

/* vCPU index of a VMM thread named @comm: "CPU n/KVM" (QEMU) or "fc_vcpu n" */
static bool vcpu_index(const char *comm, __u32 *vcpu)
{
	return (sscanf(comm, "CPU %u/KVM", vcpu) == 1 ||
		sscanf(comm, "fc_vcpu %u", vcpu) == 1) && *vcpu < PV_MAX_VCPUS;
}

/*
 * Add the vCPU threads of the guest's VMM to vcpu_threads, and confine all
 * its threads to the CPUs of -C.
 */
static void map_vcpu_threads(struct scx_pvhost *skel, int id)
{
	struct guest *g = &guests[id];
	char path[64], comm[64];
	struct dirent *de;
	__u32 nr = 0;
	DIR *dir;

	snprintf(path, sizeof(path), "/proc/%d/task", g->vmm_pid);
	dir = opendir(path);
	if (!dir)
		return;
	while ((de = readdir(dir))) {
		struct { __u32 guest, vcpu; } val = { .guest = id };
		__u32 tid = atoi(de->d_name);
		FILE *f;

		if (!tid)
			continue;
		if (nr_pool)
			sched_setaffinity(tid, sizeof(pool), &pool);
		snprintf(path, sizeof(path), "/proc/%d/task/%u/comm", g->vmm_pid, tid);
		f = fopen(path, "r");
		if (!f)
			continue;
		if (fgets(comm, sizeof(comm), f) && vcpu_index(comm, &val.vcpu) &&
		    !bpf_map_update_elem(bpf_map__fd(skel->maps.vcpu_threads), &tid, &val, BPF_ANY))
			nr++;
		fclose(f);
	}
	closedir(dir);
	if (nr != g->nr_threads)
		printf("guest %d: %s: %u vCPU threads\n", id, g->name, nr);
	g->nr_threads = nr;
	skel->bss->slot_vcpus[id] = nr;
}

/*
 * Try to register pending slot @id: once its VMM maps the file, map it
 * ourselves, (re)initialize the host's side of the shared pages and import
 * them. Return false to keep waiting.
 */
static bool try_register(struct scx_pvhost *skel, int id)
{
	struct guest *g = &guests[id];
	size_t len = PV_PAGES * getpagesize();
	struct pv_shared *shm;
	struct stat st;
	__u64 epoch;
	int ret;

	if (g->fd < 0) {
		ret = open_backing(g);
		if (ret == -EINVAL) {
			fprintf(stderr, "%s/%s: not a regular file on tmpfs or hugetlbfs, ignored\n",
				dir_path, g->name);
			drop_pending(g);
			return true;
		}
		if (ret)
			return false;
	}
	/* QEMU creates the file, then sizes it: wait for the size */
	if (fstat(g->fd, &st) || st.st_size < (off_t)PV_MEMFD_SIZE)
		return false;
	g->vmm_pid = find_vmm(g);
	if (!g->vmm_pid)
		return false;

	g->map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, g->fd, PV_DAX_OFF);
	if (g->map == MAP_FAILED) {
		perror("mmap");
		drop_pending(g);
		return true;
	}
	shm = g->map;
	/* The guest side may be live already, after a restart of the host */
	memset(&shm->host, 0, sizeof(shm->host));
	memset(shm->hvcpu, 0, sizeof(shm->hvcpu));
	if (getrandom(&epoch, sizeof(epoch), 0) != sizeof(epoch))
		epoch = time(NULL) ^ ((__u64)getpid() << 32);
	shm->host.guest_id = id;
	shm->host.version = PV_VERSION;
	shm->host.epoch = epoch;
	PV_WRITE(shm->host.magic, PV_MAGIC);

	skel->bss->import_guest = id;
	skel->bss->import_fd = g->fd;
	skel->bss->import_ret = 1;
	if (run_prog(skel->progs.pv_import) || skel->bss->import_ret) {
		fprintf(stderr, "%s: importing into the arena: %d\n", g->name,
			skel->bss->import_ret);
		munmap(g->map, len);
		drop_pending(g);
		return true;
	}
	skel->bss->slot_epoch[id] = epoch;
	skel->bss->slot_live[id] = 1;

	g->pidfd = syscall(SYS_pidfd_open, g->vmm_pid, 0);
	g->state = SLOT_LIVE;
	printf("guest %d: %s: VMM %d\n", id, g->name, g->vmm_pid);
	map_vcpu_threads(skel, id);
	return true;
}

static void unregister_guest(struct scx_pvhost *skel, int id)
{
	struct guest *g = &guests[id];
	char name[NAME_MAX + 1];

	skel->bss->slot_live[id] = 0;
	skel->bss->slot_vcpus[id] = 0;
	forget_vcpu_threads(skel, id);
	skel->bss->import_guest = id;
	run_prog(skel->progs.pv_release);
	munmap(g->map, PV_PAGES * getpagesize());
	close(g->fd);
	if (g->pidfd >= 0)
		close(g->pidfd);
	printf("guest %d: %s: VMM %d gone\n", id, g->name, g->vmm_pid);
	snprintf(name, sizeof(name), "%s", g->name);
	g->state = SLOT_FREE;
	/* A new VMM may have opened the same file before we noticed */
	add_pending(name);
}

/* Look at every file already there: guests that run across our restart */
static void scan_dir(void)
{
	struct dirent *de;
	DIR *dir;
	int fd;

	fd = dup(dir_fd);
	if (fd < 0)
		return;
	dir = fdopendir(fd);
	if (!dir) {
		close(fd);
		return;
	}
	while ((de = readdir(dir)))
		if (de->d_type == DT_REG || de->d_type == DT_UNKNOWN)
			add_pending(de->d_name);
	closedir(dir);
}

static void handle_inotify(int ifd)
{
	char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
	const struct inotify_event *ev;
	ssize_t len;
	char *p;

	while ((len = read(ifd, buf, sizeof(buf))) > 0)
		for (p = buf; p < buf + len; p += sizeof(*ev) + ev->len) {
			ev = (const struct inotify_event *)p;
			if (ev->len && !(ev->mask & IN_ISDIR))
				add_pending(ev->name);
		}
}

static void tick(struct scx_pvhost *skel)
{
	time_t now = time(NULL);
	int i;

	for (i = 0; i < PV_MAX_GUESTS; i++) {
		struct guest *g = &guests[i];

		if (g->state == SLOT_PENDING && !try_register(skel, i) &&
		    now - g->pending_since > PENDING_TIMEOUT_S) {
			if (verbose)
				printf("%s: no VMM maps it, ignored\n", g->name);
			drop_pending(g);
		}
		if (g->state != SLOT_LIVE)
			continue;
		/* Without a pidfd, poll the process */
		if (g->pidfd < 0 && kill(g->vmm_pid, 0) && errno == ESRCH) {
			unregister_guest(skel, i);
			continue;
		}
		/* vCPU threads may show up after the process, keep refreshing */
		map_vcpu_threads(skel, i);
	}
}

static void print_stats(struct scx_pvhost *skel)
{
	int i;

	for (i = 0; i < PV_MAX_GUESTS; i++) {
		struct guest *g = &guests[i];
		struct pv_shared *s = g->map;
		__u64 nr_preempted = 0;
		__u32 v, nr_vcpus;

		if (g->state != SLOT_LIVE)
			continue;
		if (PV_READ(s->guest.ready) != PV_GUEST_READY) {
			printf("host: guest %d: %s: no guest scheduler\n", i, g->name);
			continue;
		}
		nr_vcpus = PV_READ(s->guest.nr_vcpus);
		for (v = 0; v < nr_vcpus && v < PV_MAX_VCPUS; v++)
			nr_preempted += PV_READ(s->hvcpu[v].nr_preempted);
		printf("host: guest %d: %s: vcpus=%u demand=%.2f target=%u folded=%u preempted=%llu/s\n",
		       i, g->name, nr_vcpus, (double)PV_READ(s->guest.demand) / PV_DEMAND_ONE,
		       PV_READ(s->host.target_vcpus), PV_READ(s->guest.nr_folded),
		       nr_preempted - g->nr_preempted);
		g->nr_preempted = nr_preempted;
	}
	printf("host: folded vCPU threads queued: %llu, directed yields: %llu, blocked donors: %llu, capped: %llu, borrows: %llu\n",
	       (unsigned long long)skel->bss->nr_folded_runs,
	       (unsigned long long)skel->bss->nr_yields,
	       (unsigned long long)skel->bss->nr_enq_blocked,
	       (unsigned long long)skel->bss->nr_capped,
	       (unsigned long long)skel->bss->nr_borrows);
}

/* Parse a CPU list like "0-3,8,10-11" into the guests' CPU pool */
static int parse_pool(struct scx_pvhost *skel, const char *list)
{
	char *s = strdup(list), *tok, *save;
	int a, b, cpu;

	CPU_ZERO(&pool);
	nr_pool = 0;
	for (tok = strtok_r(s, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		if (sscanf(tok, "%d-%d", &a, &b) != 2)
			b = a = atoi(tok);
		for (cpu = a; cpu <= b; cpu++) {
			if (cpu < 0 || cpu >= PV_MAX_CPUS || CPU_ISSET(cpu, &pool))
				continue;
			CPU_SET(cpu, &pool);
			skel->rodata->pool_cpus[nr_pool++] = cpu;
		}
	}
	free(s);
	skel->rodata->nr_pool_cpus = nr_pool;
	return nr_pool;
}

/* Give the directory to @user, a name or a uid */
static void chown_dir(const char *user)
{
	struct passwd *pw = getpwnam(user);
	char *end;
	uid_t uid;
	gid_t gid;

	if (pw) {
		uid = pw->pw_uid;
		gid = pw->pw_gid;
	} else {
		errno = 0;
		uid = strtoul(user, &end, 10);
		SCX_BUG_ON(errno || end == user || *end, "unknown user %s", user);
		pw = getpwuid(uid);
		gid = pw ? pw->pw_gid : (gid_t)-1;
	}
	SCX_BUG_ON(fchown(dir_fd, uid, gid), "giving %s to %s", dir_path, user);
}

int main(int argc, char **argv)
{
	struct pollfd pfds[1 + PV_MAX_GUESTS];
	int i, nr_pfds, ifd, nr_pcpus = 0;
	struct scx_pvhost *skel;
	struct bpf_link *link;
	time_t last_tick = 0;
	size_t arena_sz;
	__s32 opt;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	setvbuf(stdout, NULL, _IOLBF, 0);

	skel = SCX_OPS_OPEN(pvhost_ops, scx_pvhost);

	while ((opt = getopt(argc, argv, "d:u:p:C:s:TWAvh")) != -1) {
		switch (opt) {
		case 'd':
			dir_path = optarg;
			break;
		case 'u':
			dir_user = optarg;
			break;
		case 'p':
			nr_pcpus = atoi(optarg);
			break;
		case 'C':
			SCX_BUG_ON(!parse_pool(skel, optarg), "no CPUs in %s", optarg);
			break;
		case 's':
			skel->rodata->slice_ns = strtoull(optarg, NULL, 0) * 1000;
			break;
		case 'T':
			skel->rodata->vm_fair = false;
			break;
		case 'W':
			skel->rodata->smt_whole_core = true;
			break;
		case 'A':
			skel->rodata->smt_asym_packing = true;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}
	if (nr_pcpus <= 0)
		nr_pcpus = nr_pool ?: sysconf(_SC_NPROCESSORS_ONLN);
	SCX_BUG_ON(libbpf_num_possible_cpus() > PV_MAX_CPUS, "more than %d CPUs", PV_MAX_CPUS);
	PV_SET_TOPO(skel, libbpf_num_possible_cpus());
	skel->rodata->nr_pcpus = nr_pcpus;

	SCX_BUG_ON(mkdir(dir_path, 0755) && errno != EEXIST, "creating %s", dir_path);
	dir_fd = open(dir_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	SCX_BUG_ON(dir_fd < 0, "opening %s", dir_path);
	if (dir_user)
		chown_dir(dir_user);
	ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	SCX_BUG_ON(ifd < 0 || inotify_add_watch(ifd, dir_path,
						IN_CREATE | IN_OPEN | IN_MOVED_TO) < 0,
		   "watching %s", dir_path);

	SCX_OPS_LOAD(skel, pvhost_ops, scx_pvhost, uei);
	skel->bss->arena_ubase = (unsigned long)bpf_map__initial_value(skel->maps.arena, &arena_sz);
	SCX_BUG_ON(!skel->bss->arena_ubase, "arena not mapped");

	link = SCX_OPS_ATTACH(skel, pvhost_ops, scx_pvhost);
	printf("host: watching %s, guests share %d CPUs\n", dir_path, nr_pcpus);
	scan_dir();

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		pfds[0] = (struct pollfd){ .fd = ifd, .events = POLLIN };
		nr_pfds = 1;
		for (i = 0; i < PV_MAX_GUESTS; i++)
			if (guests[i].state == SLOT_LIVE && guests[i].pidfd >= 0)
				pfds[nr_pfds++] = (struct pollfd){ .fd = guests[i].pidfd,
								   .events = POLLIN };
		if (poll(pfds, nr_pfds, 1000) > 0) {
			if (pfds[0].revents)
				handle_inotify(ifd);
			for (i = 0; i < PV_MAX_GUESTS; i++) {
				int j;

				if (guests[i].state != SLOT_LIVE || guests[i].pidfd < 0)
					continue;
				for (j = 1; j < nr_pfds; j++)
					if (pfds[j].fd == guests[i].pidfd && pfds[j].revents)
						unregister_guest(skel, i);
			}
		}
		/* New files get a chance right away, the rest once a second */
		for (i = 0; i < PV_MAX_GUESTS; i++)
			if (guests[i].state == SLOT_PENDING && guests[i].pending_since == time(NULL))
				try_register(skel, i);
		if (time(NULL) != last_tick) {
			last_tick = time(NULL);
			tick(skel);
			print_stats(skel);
		}
	}

	bpf_link__destroy(link);
	UEI_REPORT(skel, uei);
	/* Destroying the arena unpins the guests' pages */
	scx_pvhost__destroy(skel);
	for (i = 0; i < PV_MAX_GUESTS; i++)
		if (guests[i].state == SLOT_LIVE)
			munmap(guests[i].map, PV_PAGES * getpagesize());
	return 0;
}
