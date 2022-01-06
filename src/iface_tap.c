#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>
#include <linux/if_vlan.h>

#include <linux/types.h>
#include <linux/ethtool.h>


int up_iface(const char *name)
{
	struct ifreq req;
	memset(&req, 0, sizeof req);
	req.ifr_flags = IFF_UP;

	if (strlen(name) + 1 >= IFNAMSIZ) {
		fprintf(stderr, "device name is too long: %s\n", name);
		return -1;
	}
	strncpy(req.ifr_name, name, IFNAMSIZ);

	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("socket");
		return sockfd;
	}

	int err = ioctl(sockfd, SIOCSIFFLAGS, &req);
	if (err < 0) {
		perror("ioctl");
		close(sockfd);
		return err;
	}

	close(sockfd);
	return 0;
}


int set_mtu(const char *name, unsigned int mtu)
{
	struct ifreq req;
	memset(&req, 0, sizeof req);
	req.ifr_mtu = mtu;

	if (strlen(name) + 1 >= IFNAMSIZ) {
		fprintf(stderr, "device name is too long: %s\n", name);
		return -1;
	}
	strncpy(req.ifr_name, name, IFNAMSIZ);

	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("socket");
		return sockfd;
	}

	int err = ioctl(sockfd, SIOCSIFMTU, &req);
	if (err < 0) {
		perror("ioctl");
		close(sockfd);
		return err;
	}

	close(sockfd);
	return 0;
}


int netdev_get_index(const char *ifname, int *index)
{
	if (ifname == NULL) return -1;
	struct ifreq ifreq;
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		printf("unable to open control socket\n");
		return -1;
	}

	memset(&ifreq, 0, sizeof(ifreq));
	strcpy(ifreq.ifr_name, ifname);

	if (ioctl(fd, SIOCGIFINDEX, &ifreq) < 0) {
		printf("unable to get index <%s> err:%s\n", ifname, strerror(errno));
		return -1;
	}
	*index = ifreq.ifr_ifindex;

	return 0;
}

int netdev_macvtap_open(const char *ifname, int *tapfd, size_t tapfdsize)
{
	int retries = 10;
	int ifindex;
	size_t i = 0;
	char tapname[256] = {0};

	if (netdev_get_index(ifname, &ifindex) < 0)
		return -1;

	sprintf(tapname, "/dev/tap%d", ifindex);
	for (i = 0; i < tapfdsize; ++i) {
		int fd = -1;
		while (fd < 0) {
			if ((fd = open(tapname, O_RDWR)) >= 0) {
				tapfd[i] = fd;
			} else if (retries-- > 0) {
				perror("open failed\n");
				usleep(20000);
			} else {
				printf("unable to open %s macvtap %s\n", ifname, tapname);
				return -1;
			}
		}
	}

	return 0;
}

int netdev_macvtap_setup(int *tapfd, size_t tapfdsize, int vnet_hdr)
{
	unsigned int features;
	struct ifreq ifreq;
	short new_flags = 0;
	size_t i;

	for (i = 0; i < tapfdsize; ++i) {
		memset(&ifreq, 0, sizeof(ifreq));

		if (ioctl(tapfd[i], TUNGETIFF, &ifreq) < 0) {
			printf("cannot get interface macvtap tap\n");
			return -1;
		}

		new_flags = ifreq.ifr_flags;
		if (vnet_hdr) {
			if (ioctl(tapfd[i], TUNGETFEATURES, &features)){
			}
		} else {
			new_flags &=~IFF_VNET_HDR;
		}

		if (new_flags != ifreq.ifr_flags) {
			ifreq.ifr_flags = new_flags;
			if (ioctl(tapfd[i], TUNSETIFF, &ifreq) < 0) {
				printf("cannot set flags macvtap tap\n");
				return -1;
			}

		}

	}

	return 0;
}


int create_macvtap(const char *ifname, char return_name[IFNAMSIZ], unsigned int mtu)
{
	int tapfd[12] = {0};
	int tapfdsize = 1;
	int err = 0;

	if (netdev_macvtap_open(ifname, tapfd, tapfdsize) < 0) return -1;
	netdev_macvtap_setup(tapfd, tapfdsize, 0);
	strcpy(return_name, ifname);

	err = set_mtu(ifname, mtu);
	if (err < 0) {
		close(tapfd[0]);
		return err;
	}

	return tapfd[0];
}


int create_tap(const char *name, char return_name[IFNAMSIZ], unsigned int mtu)
{
	// https://raw.githubusercontent.com/torvalds/linux/master/Documentation/networking/tuntap.txt
	int fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		perror("open");
		return fd;
	}

	struct ifreq req;
	memset(&req, 0, sizeof req);
	req.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (name) {
		if (strlen(name) + 1 >= IFNAMSIZ) {
			close(fd);
			fprintf(stderr, "device name is too long: %s\n", name);
			return -1;
		}
		strncpy(req.ifr_name, name, IFNAMSIZ);
		printf("tun/tap dev name %s\n", req.ifr_name);
	}

	int err = ioctl(fd, TUNSETIFF, &req);
	if (err < 0) {
		close(fd);
		perror("ioctl");
		return err;
	}

	strncpy(return_name, req.ifr_name, IFNAMSIZ);
	return_name[IFNAMSIZ - 1] = '\0';

	err = set_mtu(return_name, mtu);
	if (err < 0) {
		close(fd);
		return err;
	}

	err = up_iface(return_name);
	if (err < 0) {
		close(fd);
		return err;
	}

	return fd;
}


