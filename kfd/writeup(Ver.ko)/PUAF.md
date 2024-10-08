# Exploiting PUAFs

## What is a PUAF primitive?
PUAF는 "physical use-after-free"의 약어입니다. 일반적인 UAF는 가상 주소(VA)에 대한 댕글링 포인터에서 비롯되지만, PUAF는 메모리 영역의 물리 주소(PA)에 대한 댕글링 포인터에서 비롯됩니다. PA 포인터가 다른 커널 데이터 구조에 저장될 수도 있지만, 여기서는 댕글링 PA 포인터가 이용 중인 사용자 프로세스의 페이지 테이블 계층의 리프 수준 페이지 테이블 항목(즉, iOS와 macOS의 경우 L3 PTE)에 직접 포함되어 있다고 가정합니다. 또한, PUAF 원시 상태로 간주되기 위해서는 해당 물리 페이지가 다시 프리 리스트에 반환된 상태여야 합니다. XNU에서는 모든 물리 메모리 페이지가 vm_page 구조체로 표현되며, 이 구조체의 vmp_q_state 필드는 페이지가 속한 큐를 결정하고, vmp_pageq 필드는 큐에서 다음과 이전 페이지에 대한 32비트 패킹 포인터를 포함합니다. XNU에서 주요 "프리 리스트"는 MAX_COLORS(128) 큐 배열로 표현되는 vm_page_queue_free이며, 실제 사용되는 프리 큐의 수는 장치 구성에 따라 다릅니다. 마지막으로, AP 비트에서 읽기 전용 접근을 가진 댕글링 PTE(예: P0 문제 2337)도 중요한 보안 취약점으로 간주되지만, 직접적으로 악용될 수는 없습니다. 따라서, 이 글에서 PUAF 원시 상태는 댕글링 PTE가 AP 비트에서 사용자 공간에 읽기/쓰기 접근 권한을 제공하는 것을 의미합니다. 요약하면, PUAF 원시 상태를 얻기 위해서는 읽기/쓰기 접근 권한을 가진 댕글링 L3 PTE와 물리 페이지가 프리 리스트에 반환된 상태에서 커널이 이를 사용하여 아무 작업이나 수행할 수 있어야 합니다.

## What to do before a PUAF exploit? - puaf_helper_give_ppl_pages()
위에서 언급한 것처럼 PUAF 원시 상태가 달성되면 해당 물리 페이지들은 아무 용도로 재사용될 수 있습니다. 그러나 상위 권한의 페이지 보호 계층(PPL)이 pmap_ppl_free_page_list에서 사용할 수 있는 프리 페이지가 부족하면, 일반 커널이 자체 프리 큐에서 페이지를 가져와 pmap_mark_page_as_ppl_page_internal()을 호출하여 PPL에 제공할 수 있습니다. 그러나 이 PPL 루틴은 주어진 페이지가 실제로 물리적 개구부 밖에서 매핑되지 않았음을 확인하며, 그렇지 않으면 "페이지에 아직 매핑이 있음" 패닉을 유발합니다. PUAF 원시 상태는 댕글링 PTE가 필요하므로, 이 검사는 항상 실패하고 커널 패닉을 유발할 것입니다. 따라서 PUAF 페이지를 얻은 후에는 이들을 PPL 소유로 표시하는 것을 피해야 합니다. 따라서 PUAF 익스플로잇을 시작하기 전에 pmap_ppl_free_page_list를 가능한 많이 채워서 PPL이 익스플로잇의 중요한 단계 동안 프리 페이지가 부족해지지 않도록 해야 합니다. 다행히도, vm_allocate()를 VM_FLAGS_FIXED 플래그와 함께 VM 맵의 허용된 VA 범위 내에서 L2 블록 크기에 정렬된 모든 주소에 대해 호출하여 쉽게 PPL 소유 페이지를 할당할 수 있습니다. 이전에 해당 L2 블록 크기에 매핑이 없었다면, PPL은 먼저 새로운 매핑을 수용하기 위해 L3 변환 테이블을 할당해야 합니다. 그런 다음, 이 매핑을 단순히 해제하면 PPL은 빈 L3 변환 테이블 페이지를 pmap_ppl_free_page_list로 다시 넣습니다. 이는 puaf.h에 위치한 puaf_helper_give_ppl_pages() 함수에서 수행됩니다.

macOS에서는 사용자 프로세스가 매핑할 수 있는 최대 VA(즉, current_map()->max_offset)가 매우 높아서 PPL 페이지 프리 리스트를 매우 많은 페이지로 채울 수 있습니다. 그러나 iOS에서는 최대 VA가 훨씬 낮아서 약 200 페이지만 채울 수 있습니다. 그럼에도 불구하고, 개인 연구를 위해 2048 PUAF 페이지를 얻도록 익스플로잇을 구성했을 때도 "페이지에 아직 매핑이 있음" 패닉이 거의 발생하지 않았습니다. PUAF 페이지 수가 많을수록 나머지 익스플로잇이 커널 읽기/쓰기 원시 상태를 달성하기가 더 쉬워집니다. 그러나 최대 신뢰성을 위해, 만약 PUAF 익스플로잇이 반복 가능하다면(예: PhysPuppet), 공격자는 소수의 페이지에서 PUAF 원시 상태를 얻은 후 커널 읽기/쓰기 원시 상태를 시도하고, 후자가 성공하지 않으면 필요한 만큼 과정을 반복할 수 있습니다.

## What to do after a PUAF exploit?
다음과 같이, 물리적 해제 후 사용(Physical Use-After-Free, PUAF) 원시 상태를 임의의 수의 물리 페이지에서 성공적으로 취득했다고 가정해 보겠습니다. 이제 어떻게 해야 할까요? 주의할 점은, `vm_page_queue_enter()` 매크로를 통해 프리 페이지들이 프리 큐의 꼬리에 추가되지만, 사용자 공간에서는 이러한 PUAF 페이지들이 프리 큐의 어느 위치에 있는지 정확히 알 수 없다는 것입니다. 이를 해결하기 위해 다음과 같은 방법을 사용할 수 있습니다:

1. 프리 큐에서 몇 페이지를 가져와서 고유하고 인식 가능한 내용을 채웁니다.
2. 댕글링 PTE를 통해 모든 PUAF 페이지를 스캔하여 그 인식 가능한 내용을 찾습니다.
3. 내용을 찾으면, 이는 프리 큐 중 하나에서 PUAF 페이지에 도달했음을 의미하므로 다음 단계로 넘어갑니다. 찾지 못하면 1단계로 돌아가서 몇 페이지를 더 가져오고, 이 과정을 PUAF 페이지를 최종적으로 찾을 때까지 반복합니다.

이 익스플로잇 단계는 vm_page_queue_free가 여러 프리 큐 배열로 구성된다는 사실을 고려하여 크게 최적화될 수 있습니다. 그러나 현재 상태에서는 익스플로잇이 프리 페이지를 4개씩 묶어 가져오도록 하여, PUAF 페이지의 1/4이 성공적으로 확보될 때까지 purgeable 소스 영역에 대해 `vm_copy()`를 호출합니다. 이는 대략적인 휴리스틱으로, PUAF 페이지의 25%를 완전히 낭비하지만, 필자의 경우 매우 잘 작동해서 이를 더 최적화할 필요는 없었습니다. 이 작업은 krkw.h에 위치한 `krkw_helper_grab_free_pages()` 함수에서 수행되며, 나중에 이를 업그레이드할 수도 있습니다.

<!-- 여기부터 PhysPuppet !-->
이제 PUAF 페이지가 확보되었을 가능성이 높으므로, 다음의 고수준 전략을 통해 PUAF 원시 상태를 더 강력한 커널 읽기/쓰기 원시 상태로 전환할 수 있습니다:

1. "흥미로운" 커널 객체를 스프레이하여, 남은 PUAF 페이지 중 하나에 재할당되도록 합니다.
2. 댕글링 PTE를 통해 PUAF 페이지를 스캔하여 "매직 값"을 찾아 성공적인 재할당을 확인하고, 대상 커널 객체가 포함된 PUAF 페이지를 식별합니다.
3. 대상 커널 객체의 non-PAC'ed 커널 포인터를 적절한 댕글링 PTE를 통해 완전히 제어 가능한 값으로 덮어씁니다. 필요하다면 PUAF 페이지 내에서 가짜 커널 객체 세트를 제작하는 것도 가능하지만, 아래 설명된 방법들은 이를 필요로 하지 않습니다.
4. 덮어쓴 커널 포인터를 사용하는 시스템 호출을 통해 커널 읽기 또는 쓰기 원시 상태를 얻습니다.

예를 들어, 필자는 PhysPuppet의 원래 익스플로잇에서 SockPuppet에서 영감을 받아 소켓 관련 객체를 타겟으로 삼았습니다. 따라서 위의 일반 단계는 아래 특정 작업으로 매핑될 것입니다:

1. `socket()` 시스템 호출을 통해 `inp_tp` 구조체를 스프레이합니다.
2. `setsockopt()` 시스템 호출을 통해 TCP_KEEPINTVL 옵션으로 설정된 `t_keepintvl` 필드에서 매직 값을 찾아 PUAF 페이지를 스캔합니다.
3. `inp6_outputopts` 필드를 덮어쓰며, 이는 `ip6_pktopts` 구조체를 가리키는 포인터입니다.
4. `getsockopt()` 시스템 호출을 통해 `IPV6_USE_MIN_MTU` 옵션으로 `inp6_outputopts->ip6po_minmtu`에서 4바이트 커널 읽기 원시 상태를 얻고, `setsockopt()` 시스템 호출을 통해 `IPV6_TCLASS` 옵션으로 `inp6_outputopts->ip6po_tclass`에서 -1에서 255 사이의 값으로 제한된 4바이트 커널 쓰기 원시 상태를 얻습니다.

그러나 이 부분의 익스플로잇에 대해 만족스럽지 않았습니다. 커널 쓰기 원시 상태가 너무 제한적이었고, 필요한 시스템 호출들(socket() 및 [get/set]sockopt())이 모두 WebContent 샌드박스에서 차단되기 때문입니다. 그러나 PhysPuppet과 달리 WebContent에서 익스플로잇 가능한 Smith의 취약점을 발견했을 때, WebContent 샌드박스에서 스프레이할 수 있는 흥미로운 커널 객체를 찾기로 결정했습니다. 위의 소켓 방법과 달리 커널 읽기 및 쓰기 원시 상태를 모두 동일한 대상 커널 객체에서 사용하는 대신, 두 가지 원시 상태를 위해 각각 별개의 객체를 찾았습니다.

다음은 `kread_kqueue_workloop_ctl` 메서드에 대한 설명입니다:

1. `kqueue_workloop_ctl()` 시스템 호출을 사용하여 `kqworkloop` 구조체를 스프레이합니다.
2. 위의 `kqueue_workloop_ctl()`에 의해 직접 설정된 `kqwl_dynamicid` 필드에서 매직 값을 찾기 위해 PUAF 페이지를 스캔합니다.
3. 스레드 구조체를 가리키는 포인터인 `kqwl_owner` 필드를 덮어씁니다.
4. `proc_info()` 시스템 호출을 사용하여 `PROC_INFO_CALL_PIDDYNKQUEUEINFO` 호출 번호로 `kqwl_owner->thread_id`에서 8바이트 커널 읽기 원시 상태를 얻습니다.

다음은 `kwrite_dup` 메서드에 대한 설명입니다:

1. `dup()` 시스템 호출을 사용하여 `fileproc` 구조체를 스프레이합니다(아무 파일 디스크립터나 복제).
2. 이번에는 `fileproc` 구조체에 대해 고유한 매직 값을 설정할 수 있는 필드가 없습니다. 따라서 구조체 전체의 예상 비트 패턴을 찾아 PUAF 페이지를 스캔합니다. 그런 다음, `fcntl()` 시스템 호출을 `F_SETFD` 명령어와 함께 사용하여 `fp_flags` 필드의 값을 업데이트하고, 성공적인 재할당을 확인하며 어떤 파일 디스크립터가 해당 `fileproc` 객체를 소유하고 있는지 식별합니다.
3. `fileproc_guard` 구조체를 가리키는 포인터인 `fp_guard` 필드를 덮어씁니다.
4. `change_fdguard_np()` 시스템 호출을 사용하여 `fp_guard->fpg_guard`에서 8바이트 커널 쓰기 원시 상태를 얻습니다. 그러나 이 방법은 0의 값을 덮어쓸 수 없으며, 어떤 값을 0으로 덮어쓸 수도 없습니다.

이 방법은 꽤 잘 작동했으며, 작성 시점에서는 이 방법들이 사용하는 모든 시스템 호출이 WebContent 샌드박스의 일부였습니다. 그러나 `proc_info()` 시스템 호출은 허용되지만, `PROC_INFO_CALL_PIDDYNKQUEUEINFO` 호출 번호는 거부됩니다. 따라서 다른 커널 읽기 원시 상태를 찾아야 했습니다. 다행히도, WebContent 샌드박스에서 허용되는 `proc_info()`의 다른 호출 번호를 살펴보는 것으로 쉽게 찾을 수 있었습니다.

다음은 `kread_sem_open` 메서드에 대한 설명입니다:

1. `sem_open()` 시스템 호출을 사용하여 `psemnode` 구조체를 스프레이합니다.
2. 이번에도 `psemnode` 구조체에 대해 고유한 매직 값을 설정할 수 있는 필드가 없습니다. 따라서 첫 8바이트에 동일한 `pinfo` 포인터가 포함되고, 두 번째 8바이트에 0으로 패딩된 4개의 연속적인 구조체를 찾아 PUAF 페이지를 스캔합니다. 그런 다음, 댕글링 PTE를 통해 `pinfo` 포인터를 4만큼 증가시키고, `proc_info()` 시스템 호출을 사용하여 현재 파일 디스크립터가 맞을 때 이름이 4글자로 이동된 포스픽스 세마포어의 이름을 검색합니다.
3. `pseminfo` 구조체를 가리키는 포인터인 `pinfo` 필드를 덮어씁니다.
4. `proc_info()` 시스템 호출을 사용하여 `PROC_INFO_CALL_PIDFDINFO` 호출 번호로 `pinfo->psem_uid` 및 `pinfo->psem_gid`에서 8바이트 커널 읽기 원시 상태를 얻습니다. 이 호출 번호는 WebContent 샌드박스에서 거부되지 않습니다.

`shm_open()`도 WebContent 샌드박스의 일부로, `sem_open()`과 거의 동일한 방식으로 커널 읽기 원시 상태를 얻는 데 사용할 수 있음을 유의하세요. 그러나 `sem_open()`이 세마포어의 소유자 필드를 통해 `current_proc()`의 주소를 더 쉽게 결정할 수 있게 합니다. 마지막으로, `kwrite_sem_open` 메서드는 `kwrite_dup` 메서드와 동일하게 작동하지만, `fileproc` 구조체가 `dup()` 시스템 호출 대신 `sem_open()` 시스템 호출로 스프레이됩니다.

다음은 `kread_kqueue_workloop_ctl` 메서드에 대한 설명입니다:

1. `kqueue_workloop_ctl()` 시스템 호출을 사용하여 `kqworkloop` 구조체를 스프레이합니다.
2. 위의 `kqueue_workloop_ctl()`에 의해 직접 설정된 `kqwl_dynamicid` 필드에서 매직 값을 찾기 위해 PUAF 페이지를 스캔합니다.
3. 스레드 구조체를 가리키는 포인터인 `kqwl_owner` 필드를 덮어씁니다.
4. `proc_info()` 시스템 호출을 사용하여 `PROC_INFO_CALL_PIDDYNKQUEUEINFO` 호출 번호로 `kqwl_owner->thread_id`에서 8바이트 커널 읽기 원시 상태를 얻습니다.

다음은 `kwrite_dup` 메서드에 대한 설명입니다:

1. `dup()` 시스템 호출을 사용하여 `fileproc` 구조체를 스프레이합니다(아무 파일 디스크립터나 복제).
2. 이번에는 `fileproc` 구조체에 대해 고유한 매직 값을 설정할 수 있는 필드가 없습니다. 따라서 구조체 전체의 예상 비트 패턴을 찾아 PUAF 페이지를 스캔합니다. 그런 다음, `fcntl()` 시스템 호출을 `F_SETFD` 명령어와 함께 사용하여 `fp_flags` 필드의 값을 업데이트하고, 성공적인 재할당을 확인하며 어떤 파일 디스크립터가 해당 `fileproc` 객체를 소유하고 있는지 식별합니다.
3. `fileproc_guard` 구조체를 가리키는 포인터인 `fp_guard` 필드를 덮어씁니다.
4. `change_fdguard_np()` 시스템 호출을 사용하여 `fp_guard->fpg_guard`에서 8바이트 커널 쓰기 원시 상태를 얻습니다. 그러나 이 방법은 0의 값을 덮어쓸 수 없으며, 어떤 값을 0으로 덮어쓸 수도 없습니다.

이 방법은 꽤 잘 작동했으며, 작성 시점에서는 이 방법들이 사용하는 모든 시스템 호출이 WebContent 샌드박스의 일부였습니다. 그러나 `proc_info()` 시스템 호출은 허용되지만, `PROC_INFO_CALL_PIDDYNKQUEUEINFO` 호출 번호는 거부됩니다. 따라서 다른 커널 읽기 원시 상태를 찾아야 했습니다. 다행히도, WebContent 샌드박스에서 허용되는 `proc_info()`의 다른 호출 번호를 살펴보는 것으로 쉽게 찾을 수 있었습니다.

다음은 `kread_sem_open` 메서드에 대한 설명입니다:

1. `sem_open()` 시스템 호출을 사용하여 `psemnode` 구조체를 스프레이합니다.
2. 이번에도 `psemnode` 구조체에 대해 고유한 매직 값을 설정할 수 있는 필드가 없습니다. 따라서 첫 8바이트에 동일한 `pinfo` 포인터가 포함되고, 두 번째 8바이트에 0으로 패딩된 4개의 연속적인 구조체를 찾아 PUAF 페이지를 스캔합니다. 그런 다음, 댕글링 PTE를 통해 `pinfo` 포인터를 4만큼 증가시키고, `proc_info()` 시스템 호출을 사용하여 현재 파일 디스크립터가 맞을 때 이름이 4글자로 이동된 포스픽스 세마포어의 이름을 검색합니다.
3. `pseminfo` 구조체를 가리키는 포인터인 `pinfo` 필드를 덮어씁니다.
4. `proc_info()` 시스템 호출을 사용하여 `PROC_INFO_CALL_PIDFDINFO` 호출 번호로 `pinfo->psem_uid` 및 `pinfo->psem_gid`에서 8바이트 커널 읽기 원시 상태를 얻습니다. 이 호출 번호는 WebContent 샌드박스에서 거부되지 않습니다.

`shm_open()`도 WebContent 샌드박스의 일부로, `sem_open()`과 거의 동일한 방식으로 커널 읽기 원시 상태를 얻는 데 사용할 수 있음을 유의하세요. 그러나 `sem_open()`이 세마포어의 소유자 필드를 통해 `current_proc()`의 주소를 더 쉽게 결정할 수 있게 합니다. 마지막으로, `kwrite_sem_open` 메서드는 `kwrite_dup` 메서드와 동일하게 작동하지만, `fileproc` 구조체가 `dup()` 시스템 호출 대신 `sem_open()` 시스템 호출로 스프레이됩니다.

이제 우리는 커널 읽기/쓰기 원시 상태를 가졌지만 몇 가지 작은 문제들이 남아 있습니다:

커널 읽기 원시 상태는 `pinfo->psem_uid` 및 `pinfo->psem_gid`에서 8바이트를 성공적으로 읽지만, `pseminfo` 구조체의 이전 및 이후 필드도 읽습니다. 이는 우리가 읽고자 하는 주소가 페이지의 매우 처음에 위치해 있을 때 문제가 될 수 있습니다. 이 경우, `psem_uid` 및 `psem_gid` 이전의 필드는 이전 가상 페이지에 위치하게 되며, 이는 매핑되지 않아 "Kernel data abort" 패닉을 유발할 수 있습니다. 물론 이러한 경우에는 수정된 커널 포인터에서 읽은 첫 번째 바이트를 사용하여 페이지를 언더플로우하지 않는 변형을 사용할 수 있습니다. 이는 `kread_sem_open_kread_u32()` 함수에서 수행됩니다.

커널 쓰기 원시 상태는 0의 값을 덮어쓸 수 없으며, 어떤 값을 0으로 덮어쓸 수도 없습니다. 이러한 시나리오에 대한 간단한 해결 방법이 있습니다. 예를 들어, `smith_helper_cleanup()` 함수는 0의 값을 덮어쓰는 해결 방법을 사용합니다. 값을 0으로 덮어쓰는 해결 방법은 독자에게 남겨둡니다.

이러한 문제들을 쉽게 극복할 수 있지만, 이러한 초기 원시 상태에서 더 나은 커널 읽기/쓰기를 부트스트랩하는 것이 좋습니다. 이는 `perf.h`에서 달성되지만, `libkfd`는 특정 iOS 버전에 대해 iPhone 14 Pro Max에서만 이 부분의 익스플로잇을 지원합니다 (`perf_init()` 함수에서 지원되는 버전 참조). 현재, 특정 글로벌 커널 객체(`perfmon_devices` 등)를 찾기 위해 해당 커널 캐시의 정적 주소를 사용하고 있습니다. 이는 데이터 포인터를 따라가면서 쉽게 찾을 수 없습니다. 같은 결과를 코드의 오프셋을 따라가면서 동적으로 달성할 수 있을 것으로 보이지만, 이는 현재 독자에게 남겨둡니다. 현재 상태에서 더 나은 커널 읽기/쓰기를 설정하는 방법은 다음과 같습니다:

1. `vm_allocate()`를 호출하여 단일 페이지를 할당합니다. 이 페이지는 나중에 사용자 공간과 커널 공간 간의 공유 버퍼로 사용됩니다. 또한 `memset()`을 호출하여 해당 가상 페이지를 fault in 하여 물리 페이지를 가져오고 해당하는 PTE를 채웁니다.
2. `open("/dev/aes_0", O_RDWR)`를 호출하여 파일 디스크립터를 엽니다. 나중에 이를 수정하여 "/dev/perfmon_core"로 리디렉션할 것이므로, 타겟 샌드박스에서 접근 가능한 모든 캐릭터 장치를 열 수 있습니다.
3. 커널 읽기 원시 상태를 사용하여 `current_proc()->p_fd.fd_ofiles[fd]->fp_glob->fg_ops->fo_kqfilter` 포인터를 따라가면서 `vn_kqfilter()` 함수의 슬라이드된 주소를 얻습니다. 여기서 "fd"는 이전 단계에서 `open()` 시스템 호출로 반환된 불투명한 파일 디스크립터입니다.
4. `vn_kqfilter()` 함수의 슬라이드된 주소에서 커널 캐시의 해당 함수의 정적 주소를 빼서 커널 슬라이드를 계산합니다. 그런 다음 커널 캐시의 베이스에 예상되는 Mach-O 헤더가 있는지 확인합니다.
5. 커널 읽기 원시 상태를 사용하여 `cdevsw` 배열을 스캔하여 `perfmon_cdevsw`의 주 인덱스를 찾습니다. 이는 항상 0x11인 것으로 보입니다.
6. 이전에 찾은 `fileglob` 구조체에서 커널 읽기 원시 상태를 사용하여 `fg->fg_data->v_specinfo->si_rdev`의 원래 `dev_t`를 검색하고, 커널 쓰기 원시 상태를 사용하여 이를 덮어써서 `perfmon_cdevsw`로 인덱싱되도록 합니다. 또한, 프로세스가 `kclose()`를 호출하기 전에 종료되면 `perfmon_dev_close()`가 호출되어 "perfmon: unpaired release" 패닉을 유발하지 않도록 `si_opencount` 필드를 1만큼 증가시킵니다.
7. 커널 읽기 원시 상태를 사용하여 유용한 전역 변수들(`vm_pages`, `vm_page_array_beginning_addr`, `vm_page_array_ending_addr`, `vm_first_phys_ppnum`, `ptov_table`, `gVirtBase`, `gPhysBase`, `gPhysSize`)과 `current_pmap()->ttep`의 TTBR0 및 `kernel_pmap->ttep`의 TTBR1을 검색합니다.
8. 그런 다음, TTBR0에서 시작하여 페이지 테이블을 수동으로 걸어가서 1단계에서 할당한 공유 페이지의 물리 주소를 찾습니다. 이전 단계에서 `ptov_table`을 검색했으므로, `phystokv()`를 사용하여 해당 물리 페이지의 커널 VA를 `physmap` 내에서 찾을 수 있습니다.
9. 마지막으로, 커널 쓰기 원시 상태를 사용하여 첫 번째 `perfmon` 장치의 `pmdv_config` 필드를 공유 페이지를 가리키도록 수정하고(`이전 단계에서 검색한 커널 VA를 사용하여`), `pmdv_allocated` 부울 필드를 `true`로 설정합니다.

이 시점에서 설정이 완료됩니다. 이제 공유 페이지에 `perfmon_config` 구조체를 작성한 다음, `PERFMON_CTL_SPECIFY` ioctl을 사용하여 임의의 커널 주소에서 1~65535 바이트를 읽을 수 있습니다. 또한, 이 기술이 `copyout()`을 내부적으로 사용하므로, 읽고 있는 영역은 `copy_validate()`의 `zone_element_bounds_check()`를 만족해야 합니다.

커널 메모리를 쓰기 위해 이제 공유 페이지에 `perfmon_config`, `perfmon_source`, `perfmon_event` 구조체를 작성한 다음, 아래 이미지에 표시된 것처럼 `PERFMON_CTL_ADD_EVENT` ioctl을 사용하여 임의의 커널 주소에 8바이트를 쓸 수 있습니다. 그러나 이 시점에서 `kwrite()`는 8의 배수인 모든 크기를 받아들일 수 있습니다. 이 메서드는 루프에서 이 기술을 수행할 것입니다.

![exploiting-puafs-figure1.png](/writeups/figures/exploiting-puafs-figure1.png)

마지막으로, `kclose()` 함수에서는 `perf_free()` 함수가 `si_rdev`와 `si_opencount` 필드를 원래 값으로 복원하여 파일 디스크립터가 닫힐 때 모든 관련 커널 객체가 제대로 정리됩니다. 그러나 만약 프로세스가 `kclose()`를 호출하기 전에 종료된다면, 이 정리 작업은 불완전할 수 있으며, 다음에 `/dev/aes_0`을 다시 `O_RDWR`로 열려고 하면 EMFILE 오류가 발생할 수 있습니다. 그러므로 프로세스가 언제든지 종료될 수 있고 여전히 커널이 깨끗한 상태로 남아 있도록, 파일 디스크립터의 장치별 커널 객체들을 수동으로 닫기 위해 커널 쓰기 원시 상태를 사용하는 것이 더 좋을 것입니다. 현재 이 부분은 독자들에게 연습 과제로 남겨져 있습니다.

![exploiting-puafs-figure2.png](/writeups/figures/exploiting-puafs-figure2.png)

## Impact of XNU mitigations on PUAF exploits

iOS 커널에서의 다양한 취약점 완화 기술들이 PUAF 기술을 막는 데 얼마나 효과적이었는지 살펴볼까요? 고려된 완화 기술은 KASLR, PAN, PAC, PPL, zone_require(), 그리고 kalloc_type()입니다:

- KASLR: 이 기술은 PUAF 기술에 직접적인 영향을 미치지 않습니다. PUAF 원시를 처음부터 얻기 위해 커널 주소를 누설할 필요가 없기 때문입니다. 물론 원하는 커널 객체의 주소를 얻기 위해 나중에 필요하지만, 그 시점에서는 PUAF 페이지에 무수히 많은 객체를 스프레이할 수 있어 이 정보를 수집하는 데 문제가 없습니다.

- PAN: 이 기술 또한 PUAF 기술에 직접적인 영향을 미치지 않습니다. 위에서 설명한 kread 및 kwrite 방법들은 모두 가짜 커널 객체를 만들어야 할 필요가 없었기 때문에 PAN의 부재가 유용하지 않았습니다. 실제로, 커널 공간에서 PUAF 페이지의 주소를 누출할 수 있는 많은 객체들이 있어 직접적으로 그 가짜 객체를 PUAF 페이지에 만들 수 있습니다.

- PAC: 제어 흐름 무결성의 형태로 PAC는 이 기술에 완전히 관련이 없습니다. 이는 데이터 전용 공격이기 때문입니다. 그러나 내 견해로는 데이터 포인터용 PAC가 이 기술에 가장 큰 영향을 미치는 완화 기술입니다. 왜냐하면 특정 구조체의 멤버들이 서명되지 않았다면, 커널 읽기/쓰기 원시를 얻기 위해 타겟으로 할 수 있는 커널 객체가 훨씬 많기 때문입니다.

- PPL: PPL은 이 기술을 막는 데 거의 아무 영향을 미치지 않습니다. 물론 PUAF 페이지가 페이지 테이블이나 다른 PPL로 보호된 구조체로 재사용되는 것을 막지만, "페이지에 여전히 매핑이 있는" 패닉을 회피하고 PUAF 페이지를 다른 흥미로운 커널 객체에 재사용하는 것은 매우 쉽습니다.

- zone_require(): 이 기술은 데이터-PAC과 유사한 영향을 PUAF 기술에 미칩니다. PUAF 페이지 내에서 커널 포인터를 위조하는 것을 방지하기 위해 이 함수로 검증되는 경우에 해당합니다.

- kalloc_type(): 이 기술은 이 기술과는 관련이 없습니다. 이는 가상 주소 재사용에 대한 보호를 제공하며, 물리 주소 재사용과는 상관이 없습니다.

결론적으로, iOS 커널에서의 다양한 취약점 완화 기술들은 PUAF 기술을 막는 데 일부 도움이 되었지만, PAC와 같은 데이터 포인터용 보호 기술이 가장 큰 영향을 미쳤습니다. 그러나 여전히 PUAF 기술을 통해 커널 읽기/쓰기 원시를 얻는 것이 가능했습니다.

## Appendix: Discovery of the PUAF primitive

우선, 이 프리미티브를 처음 발견했다고 주장하지 않습니다. 제가 알기로는 Google Project Zero의 Jann Horn이 최초로 댕글링 PTE 취약성을 공개적으로 보고하고 공개한 연구자입니다:

- P0 이슈 2325, 2022년 6월 29일 보고, 2022년 8월 24일 공개.
- P0 이슈 2327, 2022년 6월 30일 보고, 2022년 9월 19일 공개.

또한, TLB 플러싱 버그는 PUAF 프리미티브의 변형으로 간주될 수 있으며, Jann Horn이 더 일찍 발견했습니다:

- P0 이슈 1633, 2018년 8월 15일 보고, 2018년 9월 10일 공개.
- P0 이슈 1695, 2018년 10월 12일 보고, 2018년 10월 29일 공개.

iOS의 경우, Ian Beer가 읽기 전용 접근 권한으로 댕글링 PTE 취약성을 최초로 공개한 연구자로 보입니다:

- P0 이슈 2337, 2022년 7월 29일 보고, 2022년 11월 25일 공개.

다른 연구자들이 이와 유사한 취약성을 더 일찍 발견했을 가능성도 있지만, 제가 찾을 수 있었던 가장 초기의 사례는 위와 같습니다. 저는 Ian Beer의 이슈가 공개되기 전에 PhysPuppet을 Apple에 보고했으며, 그 당시 Jann Horn의 연구에 대해 알지 못했습니다. 따라서, 다른 연구자들에게 도움이 될 수 있도록 이 강력한 프리미티브를 어떻게 발견했는지 공유하고자 합니다. 2022년 상반기에 취약성 연구를 시작하면서 SMBClient 커널 확장에서 여러 버퍼 오버플로와 in-kernel NFS 클라이언트에서 UAF(정상적인 VA 재사용 UAF) 취약성을 발견했습니다. 하지만 당시에는 익스플로잇 경험이 거의 없었고 Apple이 이미 많은 고전적인 메모리 손상 취약성에 대한 완화 조치를 취했기 때문에 이를 어떻게 익스플로잇할지 몰랐습니다. 제 POC는 "원클릭" 원격 커널 패닉만을 유발했지만, 이는 금방 만족스럽지 않았습니다. 따라서 2022년 하반기에는 XNU 커널에서 더 나은 로직 버그를 찾기로 결심했습니다. 특히 Brandon Azad의 블로그 포스트 "One Byte to rule them all"에서 영감을 받아 물리 메모리를 공격하려 했습니다. 그러나 그의 기술은 임의의 물리 매핑 프리미티브를 얻기 위해 1바이트 선형 힙 오버플로 프리미티브를 요구했습니다. 저는 메모리 손상을 피하고 싶었기 때문에 사용자 프로세스가 자신의 PTE에 입력된 물리 주소를 제어할 수 있는 다른 로직 버그를 찾기로 했습니다. vm_map과 pmap 코드를 여러 번 읽은 끝에 임의의 물리 매핑 프리미티브를 초기 프리미티브로 얻는 것은 비현실적이라는 결론에 도달했습니다. 다행히도 바로 그 후에 엄청난 행운이 찾아왔습니다!

vm_map.c의 코드를 다시 읽던 중, 많은 함수들이 vm_map_entry 구조체의 시작 주소와 종료 주소가 페이지 정렬되어 있는지 확인하는 것을 발견했습니다(예: vm_map_enter(), vm_map_entry_insert(), vm_map_entry_zap() 등). 이러한 확인 작업이 릴리스 빌드에서는 활성화되지 않기 때문에, VM 맵에 "정렬되지 않은 항목"을 마법처럼 생성할 수 있다면 어떤 일이 일어날지 궁금했습니다. 예를 들어, vme_start 필드가 페이지 정렬된 주소 A와 같지만 vme_end 필드가 A + PAGE_SIZE + 1인 경우, vm_fault() 및 vm_map_delete() 함수는 어떻게 동작할까요? 놀랍게도, 이 조건은 간단하게 댕글링 PTE로 이어질 수 있다는 것을 깨달았습니다. 물론, 이 당시에는 이는 단지 아이디어에 불과했지만, 매우 유망한 아이디어였습니다! 그래서 공격자가 이러한 정렬되지 않은 항목을 생성할 수 있는 로직 버그를 찾기로 했습니다. 처음에는 WebContent 샌드박스에서 접근 가능한 모든 공격 표면을 조사했지만 찾지 못했습니다. 그러나 WebContent에서 접근 가능한 취약점을 포기한 후, 빠르게 MIG 루틴 mach_memory_object_memory_entry_64()에서 PhysPuppet의 취약점을 발견했습니다. 이 내용은 별도의 보고서에서 자세히 다룹니다.

그 후, PUAF 프리미티브를 달성한 기존 익스플로잇을 온라인에서 확인해봤습니다. 당시에는 iOS에 대한 예제를 찾을 수 없었지만, Jann Horn의 Mali 이슈를 발견했습니다. 간단한 리눅스 메모리 손상 버그를 익스플로잇하는 그의 블로그 포스트도 빠르게 훑어봤습니다. 저는 이것이 사용자 공간이 아닌 커널 공간의 댕글링 PTE를 포함한 PUAF 프리미티브의 변형이라고 잘못 생각했습니다. 나중에야 이것이 단순한 일반적인 UAF였음을 깨달았지만, 그는 페이지 할당자를 통해 피해 페이지를 페이지 테이블로 재할당하여 익스플로잇했습니다. 이는 formidable PPL 때문에 iOS에서는 불가능하다고 생각했지만, Ned Williamson의 SockPuppet 익스플로잇에 이미 익숙했기 때문에 댕글링 PTE를 PUAF 페이지 내 소켓 관련 객체로 재할당하고, getsockopt()/setsockopt() 시스템 호출을 사용하여 각각 커널 읽기/쓰기 프리미티브를 얻을 수 있을 것이라는 확신이 있었습니다.
