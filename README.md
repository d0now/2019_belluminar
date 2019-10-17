# Belluminar pwnable task.

@donow

Task name : Super modern service?

## Task Information

이 문제는 Linux에서 최근 implementation된 Binder IPC driver의 서비스에서 발생할 수 있는 문제에 대해 다룬 취약점입니다.
Binder client로부터 받는 데이터가 잘못 파싱 될 경우 발생하는 문제를 어떻게 Exploit 하여 Privilige escalation이 가능한지에 대해 구현 해야합니다.
취약점의 유형은 race condition + use-after-free 입니다.
서비스는 요청을 받을 시 thread spawn을 통해 ipc를 처리합니다.
이 때, 잘못된 locking으로 인해 발생하는 use-after-free에 대해 다룰 것입니다.

#### References

[1] Android binder service manager source code.
https://android.googlesource.com/platform/frameworks/native/+/brillo-m7-release/cmds/servicemanager