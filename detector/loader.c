#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <unistd.h>

int main() {
  const char *ifaces[] = { "eth0", "wlp1s0" };
  int num_ifaces = 2;
  struct bpf_object *obj;
  int prog_fd, err;

  obj = bpf_object__open_file("detector.bpf.o", NULL);
  if (!obj) {
    fprintf(stderr, "Error opening BPF object file\n");
    return 1;
  }

  if (bpf_object__load(obj)) {
    fprintf(stderr, "Error loading BPF object\n");
    return 1;
  }

  // Iterate over the programs to get the first one
  struct bpf_program *prog = NULL;
  bpf_object__for_each_program(prog, obj) {
    break;
  }
  if (!prog) {
    fprintf(stderr, "No BPF program found in object\n");
    return 1;
  }

  prog_fd = bpf_program__fd(prog);
  if (prog_fd < 0) {
    fprintf(stderr, "Error getting program FD\n");
    return 1;
  }

  // Attach the XDP program to each interface.
  for (int i = 0; i < num_ifaces; i++) {
    int ifindex = if_nametoindex(ifaces[i]);
    if (ifindex == 0) {
      fprintf(stderr, "Interface %s not found\n", ifaces[i]);
      continue;
    }
    err = bpf_xdp_attach(ifindex, prog_fd, 0, NULL);
    if (err < 0) {
      fprintf(stderr, "Error attaching to %s\n", ifaces[i]);
    } else {
      printf("Successfully attached to %s\n", ifaces[i]);
    }
  }

  printf("Running... Press Ctrl+C to exit.\n");
  while (1)
    sleep(1);

  return 0;
}
