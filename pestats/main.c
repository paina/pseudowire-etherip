/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Ginzado Co., Ltd.
 * Copyright(c) 2026 Taisuke "paina" SATO
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/un.h>

#define PESTATS_UNIX_SOCKET_PATH "/run/pestats.socket"

typedef unsigned long long int uint64_t;

struct pestats {
	uint64_t ul_rx_packets;
	uint64_t ul_rx_bytes;
	uint64_t ul_rx_bpdus;
	uint64_t ul_tx_packets;
	uint64_t ul_tx_bytes;
	uint64_t ul_tx_errors;
	uint64_t dl_rx_packets;
	uint64_t dl_rx_bytes;
	uint64_t dl_rx_bpdus;
	uint64_t dl_tx_packets;
	uint64_t dl_tx_bytes;
	uint64_t dl_tx_errors;
	uint64_t encap_frags;
	uint64_t decap_reasms;
	uint64_t decap_reasm_drops;
	uint64_t encap_noready_drops;
};

int
main(int argc, char *argv[]) {
	int ret;
	struct sockaddr_un clientsa;
	const char *path = PESTATS_UNIX_SOCKET_PATH;

	int clientfd;

	if (argc > 1)
		path = argv[1];

	memset(&clientsa, 0, sizeof(clientsa));

	if (strlen(path) >= sizeof(clientsa.sun_path)) {
		printf("socket path too long\n");
		exit(-1);
	}

	clientfd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (clientfd < 0) {
		printf("socket failed\n");
		exit(-1);
	}

	clientsa.sun_family = AF_LOCAL;
	strcpy(clientsa.sun_path, path);

	ret = connect(clientfd, (struct sockaddr *)&clientsa, sizeof(clientsa));
	if (ret < 0) {
		printf("connect failed\n");
		close(clientfd);
		exit(-1);
	}

	int req = 0;
	ret = send(clientfd, &req, sizeof(req), 0);
	if (ret != sizeof(req)) {
		printf("send failed\n");
		close(clientfd);
		exit(-1);
	}

	struct pestats pestats;
	ret = recv(clientfd, &pestats, sizeof(pestats), 0);
	if (ret != sizeof(pestats)) {
		printf("recv failed\n");
		close(clientfd);
		exit(-1);
	}

	printf("pestats.ul_rx_packets       %20lld\n", pestats.ul_rx_packets);
	printf("pestats.ul_rx_bytes         %20lld\n", pestats.ul_rx_bytes);
	printf("pestats.ul_rx_bpdus         %20lld\n", pestats.ul_rx_bpdus);
	printf("pestats.ul_tx_packets       %20lld\n", pestats.ul_tx_packets);
	printf("pestats.ul_tx_bytes         %20lld\n", pestats.ul_tx_bytes);
	printf("pestats.ul_tx_errors        %20lld\n", pestats.ul_tx_errors);
	printf("pestats.dl_rx_packets       %20lld\n", pestats.dl_rx_packets);
	printf("pestats.dl_rx_bytes         %20lld\n", pestats.dl_rx_bytes);
	printf("pestats.dl_rx_bpdus         %20lld\n", pestats.dl_rx_bpdus);
	printf("pestats.dl_tx_packets       %20lld\n", pestats.dl_tx_packets);
	printf("pestats.dl_tx_bytes         %20lld\n", pestats.dl_tx_bytes);
	printf("pestats.dl_tx_errors        %20lld\n", pestats.dl_tx_errors);
	printf("pestats.encap_frags         %20lld\n", pestats.encap_frags);
	printf("pestats.decap_reasms        %20lld\n", pestats.decap_reasms);
	printf("pestats.decap_reasm_drops   %20lld\n", pestats.decap_reasm_drops);
	printf("pestats.encap_noready_drops %20lld\n", pestats.encap_noready_drops);

	close(clientfd);

	return 0;
}
