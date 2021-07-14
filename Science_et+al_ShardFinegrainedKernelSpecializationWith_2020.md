[[Science_et+al_ShardFinegrainedKernelSpecializationWith_2020]]

# [SHARD: Fine-Grained Kernel Specialization with Context-Aware Hardening]()

## [[Muhammad Abubakar Adil Ahmad Pedro Fonseca Dongyan Xu Department of Computer Science]]; [[CERIAS]]; [[Purdue University {mabubaka]] et al.

### 2020

## Abstract
With growing hardware complexity and ever-evolving user requirements, the kernel is increasingly bloated which increases its attack surface. Despite its large size, for specific applications and workloads, only a small subset of the kernel code is actually required. Kernel specialization approaches exploit this observation to either harden the kernel or restrict access to its code (debloating) on a per-application basis. However, existing approaches suffer from coarse specialization granularity and lack strict enforcement which limits their effectiveness.

## Key concepts
#control_flow_integrity; #run_time; #control_flow_graph; #attack_surface; #virtual_machine; #linux_kernel; #extended_page_tables; #static_analysis; #compile_time; #linux_test_project; #trusted_computing_base

## Quote
> Our analysis reveals that for half the system calls, SHARD exposes between 0 − 0.2% of assembly instructions in the Linux kernel


## Key points
- Operating system kernels have seen an exponential growth during the last two decades
- SHARD exposes 181× less kernel code, on average, than the native linux kernel, which is an order of magnitude better than existing work on kernel debloating [^30]
- Our analysis reveals that for half the system calls, SHARD exposes between 0 − 0.2% of assembly instructions in the Linux kernel
- In contrast to SHARD, the coarse debloating employed by previous kernel debloating systems, reveals a constant and large attack surface, which represents the cumulative sum of all kernel code that an application requires during execution
- This paper presents SHARD, a run-time fine-grained kernel specialization system that combines debloating with contextaware hardening to prevent kernel attacks
- A naive solution would be to modify RESTRICTED and UNRESTRICTED pages to use integer-indexing as well. Such approach would incur considerable overhead, up to 40% [^29], for code pages that otherwise would execute at near-native speed
- SHARD achieves an order of magnitude higher attack surface reduction than prior work and implements strict enforcement

## Synopsis

### 1 Introduction
Operating system kernels have seen an exponential growth during the last two decades.
In the context of the kernel, debloating the kernel code for specific applications [^30], [^36], can reduce the kernel code to 8.89% of its native size and prevent attackers from exploiting many kernel vulnerabilities without hindering application functionality.
Fine-grained specialization, at the system call and application-level, significantly reduces the amount of kernel code exposed to attackers at any given point.
In addition to employing fine-grained specialization, SHARD addresses the challenge of identifying the parts of the kernel that a system call, invoked by a specific application, should be allowed to execute, i.e., the kernel coverage of system calls.
SHARD implements context-aware hardening, a new technique to address the limitations of program analysis and dynamic profiling techniques on complex code, such as kernels.
Context-aware hardening dynamically hardens kernel code for suspicious executions, i.e., profiling or static analysis could not determine that the execution should be allowed or not.
Rity analysis. §10 discusses the performance evaluation.§11, §12 and §13 discuss limitations, related work, and conclude

### 2 Background on Kernel Specialization
Kernel specialization approaches to improve system security rely on either hardening [^39], [^52] or debloating [^30], [^36], [^36], [^38], [^62].
Debloating approaches only allow the execution of kernel code that a certain application, or group of applications, requires.
Previous debloating work enforces kernel specialization either at compile-time [^37], [^38], [^53] or run-time [^30], [^36], [^62].
Both approaches rely on an analysis phase to identify relevant kernel code for a set of applications, by executing the applications under representative workloads or by using static analysis techniques, such as control-flow graph analysis.
While run-time approaches create multiple versions of the kernel and dynamically switch the system’s kernel-view whenever the executed application changes

### 2.1 Limitations of Existing Approaches
Despite extensive work on specialization techniques [^30], [^36],[^37],[^38], [^53], [^62], existing kernel specialization techniques, as summarized in Table 1, are limited to coarse specialization and do not provide strict debloating enforcement, which seriously limits their effectiveness.
To demonstrate the security impact of this limitation, we devise an experiment employing single-view kernel specialization for two popular applications, the NGINX [^16] web server and the Redis [^17] key-value store.
In this experiment, the applications can only access the required kernel code, as determined through dynamic profiling of application workloads.
The static technique constructs a call graph of the kernel and identifies the kernel code that is reachable for each system call
This technique fails to precisely resolve indirect call sites and data-dependent paths; it over-estimates the required kernel code and might allow illegitimate executions during run-time.

### 3 Fine-grained System Call Specialization
SHARD employs fine-grained specialization by providing different kernel-views depending on the application running and the currently executing system call.
We observe that system calls providing distinct services do not share much kernel code.
In the case of Redis, read, which implements file and network I/O operations, shares only 6.8% (4.9k out of 72.1k) of its instructions with exit_group, which exits all process threads.
Given the disparity in kernel code coverage across system calls, system call-level specialization provides an opportunity to significantly reduce exposure to attacks.
Since system call-only specialization must support both NGINX and Redis, it would provide access to all instructions executable by write across both applications.
Ignoring the application dimension would inflate the attack surface in many scenarios

### 4 Context-aware Hardening
SHARD employs context-aware hardening to address the uncertainty of whether code is reachable from a particular system call.
SHARD analyzes the kernel using both static analysis techniques and dynamic workload-based profiling, to determine the accessibility of kernel code per-system call.
The reachable nodes are the kernel functions executed during dynamic workload-based profiling.
Static analysis can conclude that some functions are not reachable from a certain system call; those are labeled unreachable.
Reachable constitutes a very small portion of the kernel’s code — only 0.49% and 0.60% of the native kernel’s instructions are reachable, on average, for Redis and NGINX, respectively (Table 3).
They provide very few ROP gadgets and can be more tested for correctness.
Note that other techniques can be applied to implement context-aware hardening

### 5 System Model
We assume that controlling the client-facing application process is not enough because the application is sandboxed (e.g., Native Client [^60], Linux containers [^45]), the adversary needs to control the system’s kernel to attack the provider.
The service provider may need to run trusted supporting services on the same machine that do not accept input from the adversarial clients and are sandboxed from direct attacks by the untrusted application.
The adversary is capable of launching control-flow hijacks against the system’s kernel.
Such attacks redirect the program’s control-flow to an arbitrary location by reusing the code in the memory.
We assume that the SHARD framework and the hardware is trusted and beyond the control of the adversary.
The adversary does not have physical access to the machine, hardware attacks are out-of-scope

### 7.1 Overview
The SHARD framework consists of an offline analysis phase to generate specialized configurations for each target application and an online phase that enables, during run-time, kernel specialization and context-aware hardening based on the generated configurations.
The SHARD monitor performs three tasks: (a) track the context switches involving the untrusted application and its system call invocations, (b) specialize the kernel-view of the untrusted application on each system call, and (c) implement kernel context-aware hardening using control-flow integrity [^20] during a system call if, and when, it executes potentially reachable code.
On each system call invoked by the untrusted application, SHARD transparently replaces the kernel’s code pages based on the application’s configuration, as determined by the offline analysis ( 5 ).
This step debloats the kernel and allows SHARD to detect kernel transitions to potentially reachable code.
When the kernel execution returns from potentially reachable code to reachable code, SHARD replaces the hard-

### 7.2 Offline Analysis
This section describes how SHARD generates a target application’s kernel configuration, which outlines the kernel code required by the application on a per-system call basis.
SHARD implements two main analysis stages: (a) static control-flow graph generation and (b) dynamic profiling using application workloads.
SHARD statically analyzes the kernel to create a control-flow graph (CFG) of the kernel.
SHARD leverages a two-layered type analysis algorithm [^42] to generate the CFG
This two-layered analysis exploits the kernel’s extensive use of struct types for function pointer storage, to significantly increase precision over previous approaches [^55].
SHARD executes the target applications using representative workloads to identify the reachable kernel code during each invoked system call.
Since SHARD relies on compile-time instrumentation, our current implementation does not specialize kernel code written in assembly and considers it reachable

### 7.3 Offline Kernel Instrumentation
SHARD compiles three versions of each kernel code page, UNRESTRICTED, RESTRICTED, and HARDENED, using the unmodified kernel’s source code.
UNRESTRICTED code pages are still minimally instrumented to track context switches to untrusted applications as well as padded with NOP instructions to align code with the RESTRICTED and HARDENED versions.
SHARD enforces CFI on forward indirect control-flow transfers using a technique that is based on Restricted Pointer Indexing (RPI) [^29], [^56], while protecting backwards return transfers using the shadow stack.SHARD’s hardening prevents both ROP and JOP attacks.
Traditional RPI uses integer-based indexing into a call target table for indirect control-flow transfers
Such indexing would raise compatibility issues when passing function pointers from UNRESTRICTED and RESTRICTED to HARDENED code pages, because the former use function addresses.
Mitigations exist against this problem [^24], at slightly higher performance costs

### 7.4 Run-time Monitor
The SHARD monitor executes in VMX root mode to track the execution of untrusted applications, as well as enforce debloating and context-aware hardening.
On system call invocations by the untrusted application, the monitor switches all kernel code pages to RESTRICTED, based on the specific system call and application configuration to enforce debloating by allowing only reachable code to execute.
If the attempt was towards a potentially reachable code path, SHARD enforces contextaware hardening by (a) implementing an initial CFI check using the CPU Last Branch Record (LBR) and (b) switching the kernel-view to HARDENED.
If it is not, SHARD terminates the program, otherwise, switches the RESTRICTED versions of the kernel’s code pages to their HARDENED versions

### 8 Implementation
SHARD’s implementation consists of a static analyzer, a dynamic profiler, an LLVM instrumentation pass, and a run-time.
Static analyzer Dynamic profiler Offline kernel instrumentation Run-time monitor.
The analysis algorithm divides indirect calls based on whether they load function pointers from a struct or not.
For the former case, all call pointers loaded from a particular field of a structure are matched with all functions stored to that field.
Furthemore, we wrote an LLVM-5 [^41] instrumentation pass to instrument the kernel and create different types of code page versions.
The run-time monitor reserves a random 400KB memory region within the guest for shadow stacks.
Please refer to existing sources [^24], [^64] for a full entropy analysis of randomization-based shadow stack protection, as well as its limitations and other approaches

### 9 Security Evaluation
SHARD’s goal is to restrict the attacker capabilities to conduct control-flow hijacks by reducing the amount of kernel code exposed and employing context-aware hardening through CFI.

### 9.1 Attack Surface Reduction
SHARD restricts the attack surface to the reachable code. In particular, SHARD disables the unreachable code at every system call, while it hardens the potentially reachable code through control-flow integrity (CFI).
We use two popular real-world applications, NGINX [^16] web server and Redis [^17] keyvalue store.
To dynamically profile these applications, we used the ab [^1] and redis-benchmark suites, respectively.
To estimate the attack surface of system call-only debloating (AssortedSD in Figure 7), we calculate the upper bound of the kernel code required for each system call by combining the dynamic profiles of NGINX, Redis, and the Linux Test Project (LTP) [^40].
We determine the attack surface of SHARD (NGINXSHARD and RedisSHARD in Figure 7) by determining the reachable code at each system call through dynamic profiling of the test applications

### Results
Our analysis reveals that for half the system calls, SHARD exposes between 0 − 0.2% of assembly instructions in the Linux kernel.
In contrast to SHARD, the coarse debloating employed by previous kernel debloating systems, reveals a constant and large attack surface, which represents the cumulative sum of all kernel code that an application requires during execution.
While system call-only debloating alternative performs similar to SHARD for simpler system calls such as setuid, dup, which only execute a few internal kernel functions, it performs much worse for more complex system calls.
The reason is that complex system calls implement multiple functions, using many kernel functions, most of which are not required by a specific application

### 9.2 ROP and JOP Gadget Analysis
This section analyzes the ROP and JOP gadgets exposed by SHARD as well as system call and existing application-only kernel debloating approaches.
Note that reduction in ROP and JOP gadgets is not a comprehensive metric for reduction in attacks since a few gadgets are enough for meaningful exploits [^58],[^59].
Such analysis aids in SHARD’s comparison with existing approaches [^21], [^31], [^36], [^46], [^47], [^50] that provide such gadget analysis.
The evaluation setup, methodology, and applications are the same as §9.1

### Results
SHARD shows a reduction of 149× and.
183× considering NGINX and Redis, respectively, which is an order of magnitude better than existing application-focused and system call-only debloating

### 9.3 Attack Evaluation and Analysis
This section describes how SHARD prevents control-flow hijacks, which require kernel vulnerabilities and exploit payloads, through an attack analysis.
These vulnerabilities include out-ofbounds access such as buffer overflows, use-after-free access for a dangling pointer, and double-free issues.
SHARD is only susceptible to attacks using the payload P2 and the exposed 5 vulnerabilities (V3, V6, V8, V9, and V10), as both the payload and the vulnerabilities are reachable in these applications.
Our analysis indicates that SHARD can invalidate many exploit payloads and vulnerabilities, it is highly effective at thwarting control-flow hijacks, despite low overhead (§10).
We attempted six control-flow hijacks using NGINX and Redis.
SHARD successfully prevented all six attacks because the payload was unreachable for both application; jumps to the payload were caught by SHARD

### 10 Evaluation
This section describes the experimental setup for SHARD (§10.1), evaluates its overhead through micro-benchmarks.
(§10.2) and real-world applications (§10.3), and evaluates the impact of profiling accuracy (§10.4)

### 10.1 Experimental Setup
We conducted all our experiments on an Intel (R) Core (TM) i7-6500U CPU @ 2.50GHz with 4 MB of last-level cache, 8 GB of memory, and support for the Last Branch Record (LBR).
Our SHARD-protected kernel was Linux kernel v4.14, which ran inside a guest virtual machine (VM).
The VM was allocated 4 GB of memory, 1 thread, and connected to the host with a 1 Gb/s virtual connection.
SHARD’s monitor was installed on the KVM module of the host, running Linux kernel v4.15

### 10.2 Micro-benchmarks
This section analyzes the memory footprint of SHARD and the overhead of SHARD monitor’s operations.
SHARD maintains various versions of instrumented kernel code pages (i.e., UNRESTRICTED, RESTRICTED, and HARDENED) and call target tables to enforce control-flow integrity (CFI).
The main memory overhead is caused by call target tables, maintained for each indirect kernel call site, to enforce CFI.
The SHARD monitor performs 3 operations: (a) trap on context switches and system calls, (b) switch the EPT to enforce hardening and debloating, and (c) perform an LBR-based check for CFI during hardening.
This is lightweight system call that only takes 0.43 μs on average to execute in the native kernel.
The SHARD monitor implements a CFI-check using LBR, which requires referencing the two call target tables and retrieving the latest entry in the LBR, taking 1.01 μs on average

### 10.3 Real World Applications
We evaluate SHARD’s overhead while executing real-world widely-deployed applications, NGINX web server and Redis key-value store, that match our use-case scenario.
While running Redis as a trusted application (SHARD-trusted), we only observe an average overhead of 1.2%, because SHARD did not trap its execution.
Unlike Redis, which successively calls the same system call, we observe (Figure 11) a high number of traps which incur EPT switches (i.e., NGINX invokes distinct system calls successively).
Running NGINX as a trusted application (SHARD-trusted) incurs only 1.59% average overhead, similar to Redis.
We observe very low overhead for these applications
The reason behind this is that while we see many traps at the SHARD monitor, they were dispersed over long-running tests.
We expect such patterns to be common in many applications; for such applications SHARD’s overhead will likely be very low as well

### 10.4 Impact of Profiling Accuracy
We demonstrate the impact of profilingaccuracy on the performance of SHARD.
To evaluate the impact of a different application profile on performance, we generated a SHARD profile using Redis and ran NGINX with the generated profile.
We noticed a very high number of hardening instances with SHARD-Profredis because NGINX and Redis profiles are highly-disjoint.
We notice that the specific profiled workload, related to an application, has little impact on the application’s performance.
We show the impact on application performance when SHARD is profiled using a partial set of application workloads.
We generated a SHARD profile using half the redis-benchmarks and evaluated the performance using the rest.
Our results suggest that a partial profile is sufficient to offer high performance for an application

### 11 Limitations and Discussion
Context-aware control-flow integrity (CFI) creates a narrow window of opportunity for an attacker that full CFI would not.
While the attacker cannot execute an exploit.
Payload directly with context-aware CFI, the attacker can potentially make a malicious update to a function pointer and trick trusted applications to use the malicious function pointer.
The untrusted application is sandboxed; its interactions with the outside world are rigorously controlled.
Stack exhaustion and stack clearance checks can be applied to prevent attacks through the kernel’s stack.
These techniques, unlike CFI, are not subject to the limitations of selective hardening [^39]

### 12 Related Work
CHISEL [^31] adopts a delta debugging approach to obtain a minimal program satisfying a set of test cases
Unlike these systems, specializing at the kernel requires addressing additional complexities to provide strict enforcement guarantees with low overhead.
KCoFI [^26] uses the secure virtual architecture (SVA) [^27] to enforce CFI on the system’s kernel
Their implementation incurs a high overhead, exceeding 100% in some scenarios.
To the best of our knowledge, the Split-Kernel [^39] technique is the only previous effort in specialized kernel hardening
Both Split-Kernel and SHARD implement selective hardening of kernel execution by providing different kernel views to applications based on whether they are trusted or not.
SHARD avoids this overhead by hardening only potentially reachable code paths while allowing reachable code to execute unrestricted

### 13 Conclusion
This paper presents SHARD, a run-time fine-grained kernel specialization system that combines debloating with contextaware hardening to prevent kernel attacks.
SHARD achieves an order of magnitude higher attack surface reduction than prior work and implements strict enforcement.
SHARD incurs an overhead of only 3-10% on Redis, 10-36% on NGINX, and 0-2.7% on the SPEC CPU benchmarks

## Findings
- In the context of the kernel, debloating the kernel code for specific applications [^30], [^36], can reduce the kernel code to 8.89% of its native size and prevent attackers from exploiting many kernel vulnerabilities without hindering application functionality
- CFI uses integerbased indexing at indirect call sites instead of function pointers, which must be consistent with non-hardened code versions to allow switching; therefore, non-hardened execution would also be impacted (i.e., up to 40% overhead [^29])
- The number of ROP gadgets is reduced to 0.55% and 0.60% respectively
- The results show that in both applications 80% of the system calls utilize less than 15% of the profiled kernel code at a time
- Consider the write system call, which shares less than 33% (22.9k out of 68.2k) of its instructions across NGINX and Redis
- A naive solution would be to modify RESTRICTED and UNRESTRICTED pages to use integer-indexing as well. Such approach would incur considerable overhead, up to 40% [^29], for code pages that otherwise would execute at near-native speed
- SHARD-always-hardened incurs an additional overhead of 0.1-11% over SHARD (average increases to 11.49%)
- Furthermore, while the overhead is high (up to 37%) for smaller file sizes, it is amortized over memory and I/O overhead as the file size increases
- We notice that the specific profiled workload, related to an application, has little impact on the application’s performance (i.e., less than 2% increase in performance overhead mostly for SHARD-Profab)
- The instrumentation causes a high overhead of up to 50%

##  Confirmation of earlier findings
- CFI ensures that all control-flow transfers, at run-time, adhere to a program’s statically-analyzed control-flow graph (CFG). ^^As shown by prior work^^ [^33], CFI can effectively prevent controlflow hijacks

## Limitations
- Context-aware control-flow integrity (CFI) creates a narrow window of opportunity for an attacker that full CFI would not. In particular, while the attacker cannot execute an exploit    SHARD-Profpart<br/><br/>INCR SADD SPOP RPOP payload directly with context-aware CFI (due to SHARD’s hardening and debloating), the attacker can potentially make a malicious update to a function pointer and trick trusted applications (for which the kernel is not hardened or debloated by SHARD) to use the malicious function pointer. Although possible, we expect such attacks to be significantly difficult to perform for several reasons. In particular, the untrusted application is sandboxed (refer to §5); therefore, its interactions with the outside world are rigorously controlled. Furthermore, the attacker must both know the system call semantics of a trusted application and be able to trick the application to use the malicious function pointer in a specific scenario to conduct such attacks. We leave the investigation of these attacks to future work.

## Future work
- The attacker must both know the system call semantics of a trusted application and be able to trick the application to use the malicious function pointer in a specific scenario to conduct such attacks. We leave the investigation of these attacks to future work.

## Data and code
- https://github.com/rssys/shard


## References
[^1]: ab - apache http server benchmarking tool.https://httpd.apache.org/docs/2.4/programs/ab.html/. [[ab_Apache_0000]] [OA](https://httpd.apache.org/docs/2.4/programs/ab.html/)  [Scite](https://api.scholarcy.com/scite_url?query=ab%20%20apache%20http%20server%20benchmarking%20toolhttpshttpdapacheorgdocs24programsabhtml)

[^2]: Amd64 architecture programmer’s manual volume 3: General-purpose and system instructions. https://www.amd.com/system/files/TechDocs/24594.pdf. [[Amd64_Amd64ArchitectureProgrammerManualVolume_0000]] [OA](https://www.amd.com/system/files/TechDocs/24594.pdf)  

[^3]: Cve-2017-10661 detail. https://nvd.nist.gov/vuln/detail/CVE-2017-10661. [[Cve-2017-10661_201710661Detail_0000]] [OA](https://nvd.nist.gov/vuln/detail/CVE-2017-10661)  

[^4]: Cve-2017-11176 detail. https://nvd.nist.gov/vuln/detail/CVE-2017-11176. [[Cve-2017-11176_201711176Detail_0000]] [OA](https://nvd.nist.gov/vuln/detail/CVE-2017-11176)  

[^5]: Cve-2017-17052 detail. https://nvd.nist.gov/vuln/detail/CVE-2017-17052. [[Cve-2017-17052_201717052Detail_0000]] [OA](https://nvd.nist.gov/vuln/detail/CVE-2017-17052)  

[^6]: Cve-2017-17052 detail. https://nvd.nist.gov/vuln/detail/CVE-2018-10880. [[Cve-2017-17052_201717052Detail_0000]] [OA](https://nvd.nist.gov/vuln/detail/CVE-2018-10880)  

[^7]: Cve-2017-5123. https://security.archlinux.org/CVE-2017-5123. [[Cve-2017-5123.__0000]] [OA](https://security.archlinux.org/CVE-2017-5123)  

[^8]: Cve-2017-7308 detail. https://nvd.nist.gov/vuln/detail/CVE-2017-7308. [[Cve-2017-7308_20177308Detail_0000]] [OA](https://nvd.nist.gov/vuln/detail/CVE-2017-7308)  

[^9]: Cve-2018-17182 detail. https://nvd.nist.gov/vuln/detail/CVE-2018-17182. [[Cve-2018-17182_201817182Detail_0000]] [OA](https://nvd.nist.gov/vuln/detail/CVE-2018-17182)  

[^10]: Cve-2018-7480 detail. https://nvd.nist.gov/vuln/detail/CVE-2018-7480. [[Cve-2018-7480_20187480Detail_0000]] [OA](https://nvd.nist.gov/vuln/detail/CVE-2018-7480)  

[^11]: Cve-2019-20054 detail. https://nvd.nist.gov/vuln/detail/CVE-2019-20054. [[Cve-2019-20054_201920054Detail_0000]] [OA](https://nvd.nist.gov/vuln/detail/CVE-2019-20054)  

[^12]: Jonathansalwan/ropgadget. https://github.com/ JonathanSalwan/ROPgadget. [[Jonathansalwan/ropgadget__0000]] [OA](https://github.com/JonathanSalwan/ROPgadget)  

[^13]: L1 terminal fault / cve-2018-3615, cve-2018-3620,cve2018-3646 / intel-sa-00161. https://software.intel.com/security-software-guidance/software-guidance/l1-terminal-fault. [[Terminal_2018361520183620Cve20183646_0000]] [OA](https://software.intel.com/security-software-guidance/software-guidance/l1-terminal-fault)  

[^14]: The linux kernel enters 2020 at 27.8 million lines in git but with less developers for 2019. https://www.phoronix.com/scan.php?page=news_item&px=Linux-Git-Stats-EOY2019#:~:text=The%20Linux%20Kernel%20Enters%202020, Less%20Developers%20For%202019%20%2D%20Phoronix&text=As%20of%20this%20morning%20in,in%20at%2027.8%20million%20lines! [[The_LinuxKernelEnters2020278_2020]] [OA](https://www.phoronix.com/scan.php?page=news_item&px=Linux-Git-Stats-EOY2019#:~:text=The%20Linux%20Kernel%20Enters%202020)  

[^15]: Linux kernel grows past 15 million lines of code. https://www.tomshardware.com/news/ Linux-Linus-Torvalds-kernel-too-complex-code, 14495.html. [[Linux_LinuxKernelGrowsPast15_0000]] [OA](https://www.tomshardware.com/news/Linux-Linus-Torvalds-kernel-too-complex-code)  

[^16]: Nginx | high performance load balancer, web server, amp; reverse proxy. view-source:https://www.nginx.com/. [[Nginx_NginxHighPerformanceLoad_0000]] [OA](https://www.nginx.com/)  

[^17]: Redis. redis.io. [[Redis.__0000]] [OA](https://scholar.google.co.uk/scholar?q=Redis%20redisio) [GScholar](https://scholar.google.co.uk/scholar?q=Redis%20redisio) 

[^18]: Vulnerability details: Cve-2016-0728. https://www.cvedetails.com/cve/CVE-2016-0728/. [[Vulnerability_VulnerabilityDetailsCve20160728_0000]] [OA](https://www.cvedetails.com/cve/CVE-2016-0728/)  

[^19]: wrk - a http benchmarking tool.https://github.com/wg/wrk. [[wrk__0000]] [OA](https://github.com/wg/wrk)  

[^20]: M. Abadi, M. Budiu, Ú. Erlingsson, and J. Ligatti. Control-flow integrity principles, implementations, and applications. ACM Transactions on Information and System Security (TISSEC), 2009. [[Abadi_et+al_ControlflowIntegrityPrinciplesImplementationsApplications_2009]] [OA](https://api.scholarcy.com/oa_version?query=Abadi%2C%20M.%20Budiu%2C%20M.%20Erlingsson%2C%20%C3%9A.%20Ligatti%2C%20J.%20Control-flow%20integrity%20principles%2C%20implementations%2C%20and%20applications%202009) [GScholar](https://scholar.google.co.uk/scholar?q=Abadi%2C%20M.%20Budiu%2C%20M.%20Erlingsson%2C%20%C3%9A.%20Ligatti%2C%20J.%20Control-flow%20integrity%20principles%2C%20implementations%2C%20and%20applications%202009) [Scite](https://api.scholarcy.com/scite_url?query=Abadi%2C%20M.%20Budiu%2C%20M.%20Erlingsson%2C%20%C3%9A.%20Ligatti%2C%20J.%20Control-flow%20integrity%20principles%2C%20implementations%2C%20and%20applications%202009)

[^21]: B. A. Azad, P. Laperdrix, and N. Nikiforakis. Less is more: Quantifying the security benefits of debloating web applications. In Proceedings of the 28th USENIX Security Symposium (Security), 2019. [[Azad_et+al_LessMoreQuantifyingSecurityBenefits_2019]] [OA](https://api.scholarcy.com/oa_version?query=Azad%2C%20B.A.%20Laperdrix%2C%20P.%20Nikiforakis%2C%20N.%20Less%20is%20more%3A%20Quantifying%20the%20security%20benefits%20of%20debloating%20web%20applications%202019) [GScholar](https://scholar.google.co.uk/scholar?q=Azad%2C%20B.A.%20Laperdrix%2C%20P.%20Nikiforakis%2C%20N.%20Less%20is%20more%3A%20Quantifying%20the%20security%20benefits%20of%20debloating%20web%20applications%202019) [Scite](https://api.scholarcy.com/scite_url?query=Azad%2C%20B.A.%20Laperdrix%2C%20P.%20Nikiforakis%2C%20N.%20Less%20is%20more%3A%20Quantifying%20the%20security%20benefits%20of%20debloating%20web%20applications%202019)

[^22]: J.-J. Bai, J. Lawall, Q.-L. Chen, and S.-M. Hu. Effective static analysis of concurrency use-after-free bugs in linux device drivers. In Proceedings of USENIX Annual Technical Conference (ATC), 2019. [[Bai_et+al_EffectiveStaticAnalysisConcurrencyafterfree_2019]] [OA](https://api.scholarcy.com/oa_version?query=Bai%2C%20J.-J.%20Lawall%2C%20J.%20Chen%2C%20Q.-L.%20Hu%2C%20S.-M.%20Effective%20static%20analysis%20of%20concurrency%20use-after-free%20bugs%20in%20linux%20device%20drivers%202019) [GScholar](https://scholar.google.co.uk/scholar?q=Bai%2C%20J.-J.%20Lawall%2C%20J.%20Chen%2C%20Q.-L.%20Hu%2C%20S.-M.%20Effective%20static%20analysis%20of%20concurrency%20use-after-free%20bugs%20in%20linux%20device%20drivers%202019) [Scite](https://api.scholarcy.com/scite_url?query=Bai%2C%20J.-J.%20Lawall%2C%20J.%20Chen%2C%20Q.-L.%20Hu%2C%20S.-M.%20Effective%20static%20analysis%20of%20concurrency%20use-after-free%20bugs%20in%20linux%20device%20drivers%202019)

[^23]: T. Bletsch, X. Jiang, V. W. Freeh, and Z. Liang. Jumporiented programming: a new class of code-reuse attack. In Proceedings of the 6th ACM Symposium on Information, Computer and Communications Security, pages 30–40, 2011. [[Bletsch_et+al_JumporientedProgrammingClassCodereuseAttack_2011]] [OA](https://api.scholarcy.com/oa_version?query=Bletsch%2C%20T.%20Jiang%2C%20X.%20Freeh%2C%20V.W.%20Liang%2C%20Z.%20Jumporiented%20programming%3A%20a%20new%20class%20of%20code-reuse%20attack%202011) [GScholar](https://scholar.google.co.uk/scholar?q=Bletsch%2C%20T.%20Jiang%2C%20X.%20Freeh%2C%20V.W.%20Liang%2C%20Z.%20Jumporiented%20programming%3A%20a%20new%20class%20of%20code-reuse%20attack%202011) [Scite](https://api.scholarcy.com/scite_url?query=Bletsch%2C%20T.%20Jiang%2C%20X.%20Freeh%2C%20V.W.%20Liang%2C%20Z.%20Jumporiented%20programming%3A%20a%20new%20class%20of%20code-reuse%20attack%202011)

[^24]: N. Burow, X. Zhang, and M. Payer. Shining light on shadow stacks. arXiv preprint arXiv:1811.03165, 2018. [[Burow_et+al_ShiningLightShadowStacks_2018]] [OA](https://arxiv.org/pdf/1811.03165)  

[^25]: N. Burow, X. Zhang, and M. Payer. Sok: Shining light on shadow stacks. In 2019 IEEE Symposium on Security and Privacy (SP), pages 985–999, 2019. [[Burow_et+al_ShiningLightShadowStacks_2019]] [OA](https://api.scholarcy.com/oa_version?query=Burow%2C%20N.%20Zhang%2C%20X.%20Payer%2C%20M.%20Sok%3A%20Shining%20light%20on%20shadow%20stacks%202019) [GScholar](https://scholar.google.co.uk/scholar?q=Burow%2C%20N.%20Zhang%2C%20X.%20Payer%2C%20M.%20Sok%3A%20Shining%20light%20on%20shadow%20stacks%202019) [Scite](https://api.scholarcy.com/scite_url?query=Burow%2C%20N.%20Zhang%2C%20X.%20Payer%2C%20M.%20Sok%3A%20Shining%20light%20on%20shadow%20stacks%202019)

[^26]: J. Criswell, N. Dautenhahn, and V. Adve. Kcofi: Complete control-flow integrity for commodity operating system kernels. In Proceedings of IEEE Symposium on Security and Privacy (S&P), 2014. [[Criswell_et+al_KcofiCompleteControlflowIntegrityCommodity_2014]] [OA](https://api.scholarcy.com/oa_version?query=Criswell%2C%20J.%20Dautenhahn%2C%20N.%20Adve%2C%20V.%20Kcofi%3A%20Complete%20control-flow%20integrity%20for%20commodity%20operating%20system%20kernels%202014) [GScholar](https://scholar.google.co.uk/scholar?q=Criswell%2C%20J.%20Dautenhahn%2C%20N.%20Adve%2C%20V.%20Kcofi%3A%20Complete%20control-flow%20integrity%20for%20commodity%20operating%20system%20kernels%202014) [Scite](https://api.scholarcy.com/scite_url?query=Criswell%2C%20J.%20Dautenhahn%2C%20N.%20Adve%2C%20V.%20Kcofi%3A%20Complete%20control-flow%20integrity%20for%20commodity%20operating%20system%20kernels%202014)

[^27]: J. Criswell, A. Lenharth, D. Dhurjati, and V. Adve. Secure virtual architecture: A safe execution environment for commodity operating systems. In Proceedings of the 21st ACM Symposium on Operating Systems Principles (SOSP), 2007. [[Criswell_et+al_SecureVirtualArchitectureASafe_2007]] [OA](https://api.scholarcy.com/oa_version?query=Criswell%2C%20J.%20Lenharth%2C%20A.%20Dhurjati%2C%20D.%20Adve%2C%20V.%20Secure%20virtual%20architecture%3A%20A%20safe%20execution%20environment%20for%20commodity%20operating%20systems%202007) [GScholar](https://scholar.google.co.uk/scholar?q=Criswell%2C%20J.%20Lenharth%2C%20A.%20Dhurjati%2C%20D.%20Adve%2C%20V.%20Secure%20virtual%20architecture%3A%20A%20safe%20execution%20environment%20for%20commodity%20operating%20systems%202007) [Scite](https://api.scholarcy.com/scite_url?query=Criswell%2C%20J.%20Lenharth%2C%20A.%20Dhurjati%2C%20D.%20Adve%2C%20V.%20Secure%20virtual%20architecture%3A%20A%20safe%20execution%20environment%20for%20commodity%20operating%20systems%202007)

[^28]: T. H. Dang, P. Maniatis, and D. Wagner. The performance cost of shadow stacks and stack canaries. In Proceedings of the 10th ACM Symposium on Information, Computer and Communications Security, pages 555–566, 2015. [[Dang_et+al_PerformanceCostShadowStacksStack_2015]] [OA](https://api.scholarcy.com/oa_version?query=Dang%2C%20T.H.%20Maniatis%2C%20P.%20Wagner%2C%20D.%20The%20performance%20cost%20of%20shadow%20stacks%20and%20stack%20canaries%202015) [GScholar](https://scholar.google.co.uk/scholar?q=Dang%2C%20T.H.%20Maniatis%2C%20P.%20Wagner%2C%20D.%20The%20performance%20cost%20of%20shadow%20stacks%20and%20stack%20canaries%202015) [Scite](https://api.scholarcy.com/scite_url?query=Dang%2C%20T.H.%20Maniatis%2C%20P.%20Wagner%2C%20D.%20The%20performance%20cost%20of%20shadow%20stacks%20and%20stack%20canaries%202015)

[^29]: X. Ge, N. Talele, M. Payer, and T. Jaeger. Fine-grained control-flow integrity for kernel software. In Proceedings of the IEEE European Symposium on Security and Privacy (EuroS&P), 2016. [[Ge_et+al_FinegrainedControlflowIntegrityKernelSoftware_2016]] [OA](https://api.scholarcy.com/oa_version?query=Ge%2C%20X.%20Talele%2C%20N.%20Payer%2C%20M.%20Jaeger%2C%20T.%20Fine-grained%20control-flow%20integrity%20for%20kernel%20software%202016) [GScholar](https://scholar.google.co.uk/scholar?q=Ge%2C%20X.%20Talele%2C%20N.%20Payer%2C%20M.%20Jaeger%2C%20T.%20Fine-grained%20control-flow%20integrity%20for%20kernel%20software%202016) [Scite](https://api.scholarcy.com/scite_url?query=Ge%2C%20X.%20Talele%2C%20N.%20Payer%2C%20M.%20Jaeger%2C%20T.%20Fine-grained%20control-flow%20integrity%20for%20kernel%20software%202016)

[^30]: Z. Gu, B. Saltaformaggio, X. Zhang, and D. Xu. FACECHANGE: application-driven dynamic kernel view switching in a virtual machine. In Proceedings of the 44th Annual IEEE/IFIP International Conference on Dependable Systems and Networks, (DSN), 2014. [[Gu_et+al_FacechangeApplicationdrivenDynamicKernelView_2014]] [OA](https://api.scholarcy.com/oa_version?query=Gu%2C%20Z.%20Saltaformaggio%2C%20B.%20Zhang%2C%20X.%20Xu%2C%20D.%20FACECHANGE%3A%20application-driven%20dynamic%20kernel%20view%20switching%20in%20a%20virtual%20machine%202014) [GScholar](https://scholar.google.co.uk/scholar?q=Gu%2C%20Z.%20Saltaformaggio%2C%20B.%20Zhang%2C%20X.%20Xu%2C%20D.%20FACECHANGE%3A%20application-driven%20dynamic%20kernel%20view%20switching%20in%20a%20virtual%20machine%202014) [Scite](https://api.scholarcy.com/scite_url?query=Gu%2C%20Z.%20Saltaformaggio%2C%20B.%20Zhang%2C%20X.%20Xu%2C%20D.%20FACECHANGE%3A%20application-driven%20dynamic%20kernel%20view%20switching%20in%20a%20virtual%20machine%202014)

[^31]: K. Heo, W. Lee, P. Pashakhanloo, and M. Naik. Effective program debloating via reinforcement learning. In Proceedings of the ACM Conference on Computer and Communications Security (CCS), 2018. [[Heo_et+al_EffectiveProgramDebloatingReinforcementLearning_2018]] [OA](https://api.scholarcy.com/oa_version?query=Heo%2C%20K.%20Lee%2C%20W.%20Pashakhanloo%2C%20P.%20Naik%2C%20M.%20Effective%20program%20debloating%20via%20reinforcement%20learning%202018) [GScholar](https://scholar.google.co.uk/scholar?q=Heo%2C%20K.%20Lee%2C%20W.%20Pashakhanloo%2C%20P.%20Naik%2C%20M.%20Effective%20program%20debloating%20via%20reinforcement%20learning%202018) [Scite](https://api.scholarcy.com/scite_url?query=Heo%2C%20K.%20Lee%2C%20W.%20Pashakhanloo%2C%20P.%20Naik%2C%20M.%20Effective%20program%20debloating%20via%20reinforcement%20learning%202018)

[^32]: Intel Corporation. Intel® 64 and IA-32 Architectures Optimization Reference Manual. December 2016. [[Intel_Intel64Ia32ArchitecturesOptimization_2016]] [OA](https://scholar.google.co.uk/scholar?q=Intel%20Corporation%20Intel%2064%20and%20IA32%20Architectures%20Optimization%20Reference%20Manual%20December%202016) [GScholar](https://scholar.google.co.uk/scholar?q=Intel%20Corporation%20Intel%2064%20and%20IA32%20Architectures%20Optimization%20Reference%20Manual%20December%202016) 

[^33]: K. K. Ispoglou, B. AlBassam, T. Jaeger, and M. Payer. Block oriented programming: Automating data-only attacks. In Proceedings of the 2018 ACM Conference on Computer and Communications Security (CCS), 2018. [[Ispoglou_et+al_BlockOrientedProgrammingAutomatingDataonly_2018]] [OA](https://api.scholarcy.com/oa_version?query=Ispoglou%2C%20K.K.%20AlBassam%2C%20B.%20Jaeger%2C%20T.%20Payer%2C%20M.%20Block%20oriented%20programming%3A%20Automating%20data-only%20attacks%202018) [GScholar](https://scholar.google.co.uk/scholar?q=Ispoglou%2C%20K.K.%20AlBassam%2C%20B.%20Jaeger%2C%20T.%20Payer%2C%20M.%20Block%20oriented%20programming%3A%20Automating%20data-only%20attacks%202018) [Scite](https://api.scholarcy.com/scite_url?query=Ispoglou%2C%20K.K.%20AlBassam%2C%20B.%20Jaeger%2C%20T.%20Payer%2C%20M.%20Block%20oriented%20programming%3A%20Automating%20data-only%20attacks%202018)

[^34]: V. P. Kemerlis, G. Portokalidis, and A. D. Keromytis. kguard: lightweight kernel protection against return-touser attacks. In Proceedings of the 21st USENIX Security Symposium (Security), 2012. [[Kemerlis_et+al_KguardLightweightKernelProtectionAgainst_2012]] [OA](https://api.scholarcy.com/oa_version?query=Kemerlis%2C%20V.P.%20Portokalidis%2C%20G.%20Keromytis%2C%20A.D.%20kguard%3A%20lightweight%20kernel%20protection%20against%20return-touser%20attacks%202012) [GScholar](https://scholar.google.co.uk/scholar?q=Kemerlis%2C%20V.P.%20Portokalidis%2C%20G.%20Keromytis%2C%20A.D.%20kguard%3A%20lightweight%20kernel%20protection%20against%20return-touser%20attacks%202012) [Scite](https://api.scholarcy.com/scite_url?query=Kemerlis%2C%20V.P.%20Portokalidis%2C%20G.%20Keromytis%2C%20A.D.%20kguard%3A%20lightweight%20kernel%20protection%20against%20return-touser%20attacks%202012)

[^36]: H. Kuo, A. Gunasekaran, Y. Jang, S. Mohan, R. B. Bobba, D. Lie, and J. Walker. Multik: A framework for orchestrating multiple specialized kernels. CoRR, abs/1903.06889, 2019. [[Kuo_et+al_MultikAFrameworkOrchestratingMultiple_2019]] [OA](https://arxiv.org/pdf/1903.06889)  

[^37]: H.-C. Kuo, J. Chen, S. Mohan, and T. Xu. Set the configuration for the heart of the os: On the practicality of operating system kernel debloating. Proceedings of the ACM on Measurement and Analysis of Computing Systems, 2020. [[Kuo_et+al_ConfigurationHeartOnPracticality_2020]] [OA](https://api.scholarcy.com/oa_version?query=Kuo%2C%20H.-C.%20Chen%2C%20J.%20Mohan%2C%20S.%20Xu%2C%20T.%20Set%20the%20configuration%20for%20the%20heart%20of%20the%20os%3A%20On%20the%20practicality%20of%20operating%20system%20kernel%20debloating%202020) [GScholar](https://scholar.google.co.uk/scholar?q=Kuo%2C%20H.-C.%20Chen%2C%20J.%20Mohan%2C%20S.%20Xu%2C%20T.%20Set%20the%20configuration%20for%20the%20heart%20of%20the%20os%3A%20On%20the%20practicality%20of%20operating%20system%20kernel%20debloating%202020) [Scite](https://api.scholarcy.com/scite_url?query=Kuo%2C%20H.-C.%20Chen%2C%20J.%20Mohan%2C%20S.%20Xu%2C%20T.%20Set%20the%20configuration%20for%20the%20heart%20of%20the%20os%3A%20On%20the%20practicality%20of%20operating%20system%20kernel%20debloating%202020)

[^38]: A. Kurmus, R. Tartler, D. Dorneanu, B. Heinloth, V. Rothberg, A. Ruprecht, W. Schröder-Preikschat, D. Lohmann, and R. Kapitza. Attack surface metrics and automated compile-time OS kernel tailoring. In Proceedings of the 20th Annual Network and Distributed System Security Symposium (NDSS), 2013. [[Kuo_AttackSurfaceMetricsAutomatedCompiletime_2013]] [OA](https://api.scholarcy.com/oa_version?query=A%20Kurmus%20R%20Tartler%20D%20Dorneanu%20B%20Heinloth%20V%20Rothberg%20A%20Ruprecht%20W%20Schr%C3%B6derPreikschat%20D%20Lohmann%20and%20R%20Kapitza%20Attack%20surface%20metrics%20and%20automated%20compiletime%20OS%20kernel%20tailoring%20In%20Proceedings%20of%20the%2020th%20Annual%20Network%20and%20Distributed%20System%20Security%20Symposium%20NDSS%202013) [GScholar](https://scholar.google.co.uk/scholar?q=A%20Kurmus%20R%20Tartler%20D%20Dorneanu%20B%20Heinloth%20V%20Rothberg%20A%20Ruprecht%20W%20Schr%C3%B6derPreikschat%20D%20Lohmann%20and%20R%20Kapitza%20Attack%20surface%20metrics%20and%20automated%20compiletime%20OS%20kernel%20tailoring%20In%20Proceedings%20of%20the%2020th%20Annual%20Network%20and%20Distributed%20System%20Security%20Symposium%20NDSS%202013) [Scite](https://api.scholarcy.com/scite_url?query=A%20Kurmus%20R%20Tartler%20D%20Dorneanu%20B%20Heinloth%20V%20Rothberg%20A%20Ruprecht%20W%20Schr%C3%B6derPreikschat%20D%20Lohmann%20and%20R%20Kapitza%20Attack%20surface%20metrics%20and%20automated%20compiletime%20OS%20kernel%20tailoring%20In%20Proceedings%20of%20the%2020th%20Annual%20Network%20and%20Distributed%20System%20Security%20Symposium%20NDSS%202013)

[^39]: A. Kurmus and R. Zippel. A tale of two kernels: Towards ending kernel hardening wars with split kernel. In Proceedings of the ACM Conference on Computer and Communications Security (CCS), 2014. [[Kurmus_TaleKernelsTowardsEndingKernel_2014]] [OA](https://api.scholarcy.com/oa_version?query=Kurmus%2C%20A.%20Zippel%2C%20R.%20A%20tale%20of%20two%20kernels%3A%20Towards%20ending%20kernel%20hardening%20wars%20with%20split%20kernel%202014) [GScholar](https://scholar.google.co.uk/scholar?q=Kurmus%2C%20A.%20Zippel%2C%20R.%20A%20tale%20of%20two%20kernels%3A%20Towards%20ending%20kernel%20hardening%20wars%20with%20split%20kernel%202014) [Scite](https://api.scholarcy.com/scite_url?query=Kurmus%2C%20A.%20Zippel%2C%20R.%20A%20tale%20of%20two%20kernels%3A%20Towards%20ending%20kernel%20hardening%20wars%20with%20split%20kernel%202014)

[^40]: P. Larson. Testing linux® with the linux test project. In Ottawa Linux Symposium, page 265, 2002. [[Larson_TestingLinuxWithLinuxTest_2002]] [OA](https://api.scholarcy.com/oa_version?query=Larson%2C%20P.%20Testing%20linux%C2%AE%20with%20the%20linux%20test%20project%202002) [GScholar](https://scholar.google.co.uk/scholar?q=Larson%2C%20P.%20Testing%20linux%C2%AE%20with%20the%20linux%20test%20project%202002) [Scite](https://api.scholarcy.com/scite_url?query=Larson%2C%20P.%20Testing%20linux%C2%AE%20with%20the%20linux%20test%20project%202002)

[^41]: C. Lattner and V. Adve. Llvm: A compilation framework for lifelong program analysis & transformation. In International Symposium on Code Generation and Optimization, 2004. CGO 2004., pages 75–86. IEEE, 2004. [[Lattner_LlvmACompilationFrameworkLifelong_2004]] [OA](https://api.scholarcy.com/oa_version?query=Lattner%2C%20C.%20Adve%2C%20V.%20Llvm%3A%20A%20compilation%20framework%20for%20lifelong%20program%20analysis%20%26%20transformation%202004) [GScholar](https://scholar.google.co.uk/scholar?q=Lattner%2C%20C.%20Adve%2C%20V.%20Llvm%3A%20A%20compilation%20framework%20for%20lifelong%20program%20analysis%20%26%20transformation%202004) [Scite](https://api.scholarcy.com/scite_url?query=Lattner%2C%20C.%20Adve%2C%20V.%20Llvm%3A%20A%20compilation%20framework%20for%20lifelong%20program%20analysis%20%26%20transformation%202004)

[^42]: K. Lu, A. Pakki, and Q. Wu. Detecting missing-check bugs via semantic-and context-aware criticalness and constraints inferences. In Proceedings of the 28th USENIX Security Symposium (Security), 2019. [[Lu_et+al_DetectingMissingcheckBugsSemanticContextaware_2019]] [OA](https://api.scholarcy.com/oa_version?query=Lu%2C%20K.%20Pakki%2C%20A.%20Wu%2C%20Q.%20Detecting%20missing-check%20bugs%20via%20semantic-and%20context-aware%20criticalness%20and%20constraints%20inferences%202019) [GScholar](https://scholar.google.co.uk/scholar?q=Lu%2C%20K.%20Pakki%2C%20A.%20Wu%2C%20Q.%20Detecting%20missing-check%20bugs%20via%20semantic-and%20context-aware%20criticalness%20and%20constraints%20inferences%202019) [Scite](https://api.scholarcy.com/scite_url?query=Lu%2C%20K.%20Pakki%2C%20A.%20Wu%2C%20Q.%20Detecting%20missing-check%20bugs%20via%20semantic-and%20context-aware%20criticalness%20and%20constraints%20inferences%202019)

[^44]: A. Machiry, C. Spensky, J. Corina, N. Stephens, C. Kruegel, and G. Vigna. DRCHECKER: A soundy analysis for linux kernel drivers. In Proceedings of the 26th USENIX Security Symposium (Security), 2017. [[Machiry_et+al_DrcheckerASoundyAnalysisLinux_2017]] [OA](https://api.scholarcy.com/oa_version?query=Machiry%2C%20A.%20Spensky%2C%20C.%20Corina%2C%20J.%20Stephens%2C%20N.%20DRCHECKER%3A%20A%20soundy%20analysis%20for%20linux%20kernel%20drivers%202017) [GScholar](https://scholar.google.co.uk/scholar?q=Machiry%2C%20A.%20Spensky%2C%20C.%20Corina%2C%20J.%20Stephens%2C%20N.%20DRCHECKER%3A%20A%20soundy%20analysis%20for%20linux%20kernel%20drivers%202017) [Scite](https://api.scholarcy.com/scite_url?query=Machiry%2C%20A.%20Spensky%2C%20C.%20Corina%2C%20J.%20Stephens%2C%20N.%20DRCHECKER%3A%20A%20soundy%20analysis%20for%20linux%20kernel%20drivers%202017)

[^45]: D. Merkel. Docker: lightweight linux containers for consistent development and deployment. Linux journal, 2014. [[Merkel_DockerLightweightLinuxContainersConsistent_2014]] [OA](https://api.scholarcy.com/oa_version?query=Merkel%2C%20D.%20Docker%3A%20lightweight%20linux%20containers%20for%20consistent%20development%20and%20deployment%202014) [GScholar](https://scholar.google.co.uk/scholar?q=Merkel%2C%20D.%20Docker%3A%20lightweight%20linux%20containers%20for%20consistent%20development%20and%20deployment%202014) [Scite](https://api.scholarcy.com/scite_url?query=Merkel%2C%20D.%20Docker%3A%20lightweight%20linux%20containers%20for%20consistent%20development%20and%20deployment%202014)

[^46]: C. Qian, H. Hu, M. Alharthi, P. H. Chung, T. Kim, and W. Lee. RAZOR: A framework for post-deployment software debloating. In 28th USENIX Security Symposium (USENIX Security 19), pages 1733–1750, Santa Clara, CA, Aug. 2019. USENIX Association. [[Qian_et+al_RazorAFrameworkPostdeploymentSoftware_2019]] [OA](https://api.scholarcy.com/oa_version?query=Qian%2C%20C.%20Hu%2C%20H.%20Alharthi%2C%20M.%20Chung%2C%20P.H.%20RAZOR%3A%20A%20framework%20for%20post-deployment%20software%20debloating%202019-08) [GScholar](https://scholar.google.co.uk/scholar?q=Qian%2C%20C.%20Hu%2C%20H.%20Alharthi%2C%20M.%20Chung%2C%20P.H.%20RAZOR%3A%20A%20framework%20for%20post-deployment%20software%20debloating%202019-08) [Scite](https://api.scholarcy.com/scite_url?query=Qian%2C%20C.%20Hu%2C%20H.%20Alharthi%2C%20M.%20Chung%2C%20P.H.%20RAZOR%3A%20A%20framework%20for%20post-deployment%20software%20debloating%202019-08)

[^47]: A. Quach, A. Prakash, and L. Yan. Debloating software through piece-wise compilation and loading. In 27th USENIX Security Symposium (USENIX Security 18), pages 869–886, 2018. [[Quach_et+al_DebloatingSoftwareThroughPiecewiseCompilation_2018]] [OA](https://api.scholarcy.com/oa_version?query=Quach%2C%20A.%20Prakash%2C%20A.%20Yan%2C%20L.%20Debloating%20software%20through%20piece-wise%20compilation%20and%20loading%202018) [GScholar](https://scholar.google.co.uk/scholar?q=Quach%2C%20A.%20Prakash%2C%20A.%20Yan%2C%20L.%20Debloating%20software%20through%20piece-wise%20compilation%20and%20loading%202018) [Scite](https://api.scholarcy.com/scite_url?query=Quach%2C%20A.%20Prakash%2C%20A.%20Yan%2C%20L.%20Debloating%20software%20through%20piece-wise%20compilation%20and%20loading%202018)

[^48]: D. Rosenberg. Anatomy of a remote kernel exploit, 2011. [[Rosenberg_AnatomyRemoteKernelExploit_2011]] [OA](https://scholar.google.co.uk/scholar?q=Rosenberg%2C%20D.%20Anatomy%20of%20a%20remote%20kernel%20exploit%202011) [GScholar](https://scholar.google.co.uk/scholar?q=Rosenberg%2C%20D.%20Anatomy%20of%20a%20remote%20kernel%20exploit%202011) 

[^49]: H. Shacham. The geometry of innocent flesh on the bone: Return-into-libc without function calls (on the x86). In Proceedings of the 14th ACM conference on Computer and communications security, pages 552–561, 2007. [[Shacham_GeometryInnocentFleshBoneReturnintolibc_2007]] [OA](https://api.scholarcy.com/oa_version?query=Shacham%2C%20H.%20The%20geometry%20of%20innocent%20flesh%20on%20the%20bone%3A%20Return-into-libc%20without%20function%20calls%20%28on%20the%20x86%29%202007) [GScholar](https://scholar.google.co.uk/scholar?q=Shacham%2C%20H.%20The%20geometry%20of%20innocent%20flesh%20on%20the%20bone%3A%20Return-into-libc%20without%20function%20calls%20%28on%20the%20x86%29%202007) [Scite](https://api.scholarcy.com/scite_url?query=Shacham%2C%20H.%20The%20geometry%20of%20innocent%20flesh%20on%20the%20bone%3A%20Return-into-libc%20without%20function%20calls%20%28on%20the%20x86%29%202007)

[^50]: H. Sharif, M. Abubakar, A. Gehani, and F. Zaffar. Trimmer: application specialization for code debloating. In Proceedings of the 33rd ACM/IEEE International Conference on Automated Software Engineering, pages 329– 339, 2018. [[Sharif_et+al_TrimmerApplicationSpecializationCodeDebloating_2018]] [OA](https://api.scholarcy.com/oa_version?query=Sharif%2C%20H.%20Abubakar%2C%20M.%20Gehani%2C%20A.%20Zaffar%2C%20F.%20Trimmer%3A%20application%20specialization%20for%20code%20debloating%202018) [GScholar](https://scholar.google.co.uk/scholar?q=Sharif%2C%20H.%20Abubakar%2C%20M.%20Gehani%2C%20A.%20Zaffar%2C%20F.%20Trimmer%3A%20application%20specialization%20for%20code%20debloating%202018) [Scite](https://api.scholarcy.com/scite_url?query=Sharif%2C%20H.%20Abubakar%2C%20M.%20Gehani%2C%20A.%20Zaffar%2C%20F.%20Trimmer%3A%20application%20specialization%20for%20code%20debloating%202018)

[^51]: L. Szekeres, M. Payer, L. T. Wei, and R. Sekar. Eternal war in memory. In Proceedings of the IEEE Symposium on Security & Privacy (S&P), 2014. [[Szekeres_et+al_EternalMemory_2014]] [OA](https://api.scholarcy.com/oa_version?query=Szekeres%2C%20L.%20Payer%2C%20M.%20Wei%2C%20L.T.%20Sekar%2C%20R.%20Eternal%20war%20in%20memory%202014) [GScholar](https://scholar.google.co.uk/scholar?q=Szekeres%2C%20L.%20Payer%2C%20M.%20Wei%2C%20L.T.%20Sekar%2C%20R.%20Eternal%20war%20in%20memory%202014) [Scite](https://api.scholarcy.com/scite_url?query=Szekeres%2C%20L.%20Payer%2C%20M.%20Wei%2C%20L.T.%20Sekar%2C%20R.%20Eternal%20war%20in%20memory%202014)

[^52]: R. Ta-Min, L. Litty, and D. Lie. Splitting interfaces: Making trust between applications and operating systems configurable. In Proceedings of the 7th symposium on Operating Systems Design and Implementation (OSDI), 2006. [[Ta-Min_et+al_SplittingInterfacesMakingTrustBetween_2006]] [OA](https://api.scholarcy.com/oa_version?query=Ta-Min%2C%20R.%20Litty%2C%20L.%20Lie%2C%20D.%20Splitting%20interfaces%3A%20Making%20trust%20between%20applications%20and%20operating%20systems%20configurable%202006) [GScholar](https://scholar.google.co.uk/scholar?q=Ta-Min%2C%20R.%20Litty%2C%20L.%20Lie%2C%20D.%20Splitting%20interfaces%3A%20Making%20trust%20between%20applications%20and%20operating%20systems%20configurable%202006) [Scite](https://api.scholarcy.com/scite_url?query=Ta-Min%2C%20R.%20Litty%2C%20L.%20Lie%2C%20D.%20Splitting%20interfaces%3A%20Making%20trust%20between%20applications%20and%20operating%20systems%20configurable%202006)

[^53]: R. Tartler, A. Kurmus, B. Heinloth, V. Rothberg, A. Ruprecht, D. Dorneanu, R. Kapitza, W. SchröderPreikschat, and D. Lohmann. Automatic OS kernel TCB reduction by leveraging compile-time configurability. In Proceedings of the 8th Workshop on Hot Topics in System Dependability, (HotDep), 2012. [[R_AutomaticOsKernelTcbReduction_2012]] [OA](https://api.scholarcy.com/oa_version?query=R%20Tartler%20A%20Kurmus%20B%20Heinloth%20V%20Rothberg%20A%20Ruprecht%20D%20Dorneanu%20R%20Kapitza%20W%20Schr%C3%B6derPreikschat%20and%20D%20Lohmann%20Automatic%20OS%20kernel%20TCB%20reduction%20by%20leveraging%20compiletime%20configurability%20In%20Proceedings%20of%20the%208th%20Workshop%20on%20Hot%20Topics%20in%20System%20Dependability%20HotDep%202012) [GScholar](https://scholar.google.co.uk/scholar?q=R%20Tartler%20A%20Kurmus%20B%20Heinloth%20V%20Rothberg%20A%20Ruprecht%20D%20Dorneanu%20R%20Kapitza%20W%20Schr%C3%B6derPreikschat%20and%20D%20Lohmann%20Automatic%20OS%20kernel%20TCB%20reduction%20by%20leveraging%20compiletime%20configurability%20In%20Proceedings%20of%20the%208th%20Workshop%20on%20Hot%20Topics%20in%20System%20Dependability%20HotDep%202012) [Scite](https://api.scholarcy.com/scite_url?query=R%20Tartler%20A%20Kurmus%20B%20Heinloth%20V%20Rothberg%20A%20Ruprecht%20D%20Dorneanu%20R%20Kapitza%20W%20Schr%C3%B6derPreikschat%20and%20D%20Lohmann%20Automatic%20OS%20kernel%20TCB%20reduction%20by%20leveraging%20compiletime%20configurability%20In%20Proceedings%20of%20the%208th%20Workshop%20on%20Hot%20Topics%20in%20System%20Dependability%20HotDep%202012)

[^54]: C. Tice, T. Roeder, P. Collingbourne, S. Checkoway, Ú. Erlingsson, L. Lozano, and G. Pike. Enforcing forward-edge control-flow integrity in GCC & LLVM. In 23rd USENIX Security Symposium (USENIX Security 14), pages 941–955, 2014. [[Tice_et+al_EnforcingForwardedgeControlflowIntegrity_2014]] [OA](https://api.scholarcy.com/oa_version?query=Tice%2C%20C.%20Roeder%2C%20T.%20Collingbourne%2C%20P.%20Checkoway%2C%20S.%20Enforcing%20forward-edge%20control-flow%20integrity%202014) [GScholar](https://scholar.google.co.uk/scholar?q=Tice%2C%20C.%20Roeder%2C%20T.%20Collingbourne%2C%20P.%20Checkoway%2C%20S.%20Enforcing%20forward-edge%20control-flow%20integrity%202014) [Scite](https://api.scholarcy.com/scite_url?query=Tice%2C%20C.%20Roeder%2C%20T.%20Collingbourne%2C%20P.%20Checkoway%2C%20S.%20Enforcing%20forward-edge%20control-flow%20integrity%202014)

[^55]: W. Wang, K. Lu, and P.-C. Yew. Check it again: Detecting lacking-recheck bugs in os kernels. In Proceedings of the ACM Conference on Computer and Communications Security (CCS), 2018. [[Wang_et+al_CheckAgainDetectingLackingrecheckBugs_2018]] [OA](https://api.scholarcy.com/oa_version?query=Wang%2C%20W.%20Lu%2C%20K.%20Yew%2C%20P.-C.%20Check%20it%20again%3A%20Detecting%20lacking-recheck%20bugs%20in%20os%20kernels%202018) [GScholar](https://scholar.google.co.uk/scholar?q=Wang%2C%20W.%20Lu%2C%20K.%20Yew%2C%20P.-C.%20Check%20it%20again%3A%20Detecting%20lacking-recheck%20bugs%20in%20os%20kernels%202018) [Scite](https://api.scholarcy.com/scite_url?query=Wang%2C%20W.%20Lu%2C%20K.%20Yew%2C%20P.-C.%20Check%20it%20again%3A%20Detecting%20lacking-recheck%20bugs%20in%20os%20kernels%202018)

[^56]: Z. Wang and X. Jiang. Hypersafe: A lightweight approach to provide lifetime hypervisor control-flow integrity. In Proceedings of the IEEE Symposium on Security and Privacy (S&P), 2010. [[Wang_HypersafeALightweightApproachProvide_2010]] [OA](https://api.scholarcy.com/oa_version?query=Wang%2C%20Z.%20Jiang%2C%20X.%20Hypersafe%3A%20A%20lightweight%20approach%20to%20provide%20lifetime%20hypervisor%20control-flow%20integrity%202010) [GScholar](https://scholar.google.co.uk/scholar?q=Wang%2C%20Z.%20Jiang%2C%20X.%20Hypersafe%3A%20A%20lightweight%20approach%20to%20provide%20lifetime%20hypervisor%20control-flow%20integrity%202010) [Scite](https://api.scholarcy.com/scite_url?query=Wang%2C%20Z.%20Jiang%2C%20X.%20Hypersafe%3A%20A%20lightweight%20approach%20to%20provide%20lifetime%20hypervisor%20control-flow%20integrity%202010)

[^57]: Z. Wang, C. Wu, M. Xie, Y. Zhang, K. Lu, X. Zhang, Y. Lai, Y. Kang, and M. Yang. Seimi: Efficient and secure smap-enabled intra-process memory isolation. In 2020 IEEE Symposium on Security and Privacy (SP), pages 592–607, 2020. [[Wang_et+al_SeimiEfficientSecureSmapenabledIntraprocess_2020]] [OA](https://api.scholarcy.com/oa_version?query=Wang%2C%20Z.%20Wu%2C%20C.%20Xie%2C%20M.%20Zhang%2C%20Y.%20Seimi%3A%20Efficient%20and%20secure%20smap-enabled%20intra-process%20memory%20isolation%202020) [GScholar](https://scholar.google.co.uk/scholar?q=Wang%2C%20Z.%20Wu%2C%20C.%20Xie%2C%20M.%20Zhang%2C%20Y.%20Seimi%3A%20Efficient%20and%20secure%20smap-enabled%20intra-process%20memory%20isolation%202020) [Scite](https://api.scholarcy.com/scite_url?query=Wang%2C%20Z.%20Wu%2C%20C.%20Xie%2C%20M.%20Zhang%2C%20Y.%20Seimi%3A%20Efficient%20and%20secure%20smap-enabled%20intra-process%20memory%20isolation%202020)

[^58]: W. Wu, Y. Chen, X. Xing, and W. Zou. KEPLER: Facilitating control-flow hijacking primitive evaluation for linux kernel vulnerabilities. In Proceedings of the 28th USENIX Security Symposium (Security), 2019. [[Wu_et+al_KeplerFacilitatingControlflowHijackingPrimitive_2019]] [OA](https://api.scholarcy.com/oa_version?query=Wu%2C%20W.%20Chen%2C%20Y.%20Xing%2C%20X.%20Zou%2C%20W.%20KEPLER%3A%20Facilitating%20control-flow%20hijacking%20primitive%20evaluation%20for%20linux%20kernel%20vulnerabilities%202019) [GScholar](https://scholar.google.co.uk/scholar?q=Wu%2C%20W.%20Chen%2C%20Y.%20Xing%2C%20X.%20Zou%2C%20W.%20KEPLER%3A%20Facilitating%20control-flow%20hijacking%20primitive%20evaluation%20for%20linux%20kernel%20vulnerabilities%202019) [Scite](https://api.scholarcy.com/scite_url?query=Wu%2C%20W.%20Chen%2C%20Y.%20Xing%2C%20X.%20Zou%2C%20W.%20KEPLER%3A%20Facilitating%20control-flow%20hijacking%20primitive%20evaluation%20for%20linux%20kernel%20vulnerabilities%202019)

[^59]: W. Wu, Y. Chen, J. Xu, X. Xing, X. Gong, and W. Zou. FUZE: Towards facilitating exploit generation for kernel use-after-free vulnerabilities. In 27th USENIX Security Symposium (USENIX Security 18), pages 781–797, 2018. [[Wu_et+al_FuzeTowardsFacilitatingExploitGeneration_2018]] [OA](https://api.scholarcy.com/oa_version?query=Wu%2C%20W.%20Chen%2C%20Y.%20Xu%2C%20J.%20Xing%2C%20X.%20FUZE%3A%20Towards%20facilitating%20exploit%20generation%20for%20kernel%20use-after-free%20vulnerabilities%202018) [GScholar](https://scholar.google.co.uk/scholar?q=Wu%2C%20W.%20Chen%2C%20Y.%20Xu%2C%20J.%20Xing%2C%20X.%20FUZE%3A%20Towards%20facilitating%20exploit%20generation%20for%20kernel%20use-after-free%20vulnerabilities%202018) [Scite](https://api.scholarcy.com/scite_url?query=Wu%2C%20W.%20Chen%2C%20Y.%20Xu%2C%20J.%20Xing%2C%20X.%20FUZE%3A%20Towards%20facilitating%20exploit%20generation%20for%20kernel%20use-after-free%20vulnerabilities%202018)

[^60]: B. Yee, D. Sehr, G. Dardyk, J. B. Chen, R. Muth, T. Ormandy, S. Okasaka, N. Narula, and N. Fullagar. Native client: A sandbox for portable, untrusted x86 native code. In Proceedings of the 30th IEEE Symposium on Security and Privacy (S&P), 2009. [[Yee_et+al_NativeClientASandboxPortable_2009]] [OA](https://api.scholarcy.com/oa_version?query=Yee%2C%20B.%20Sehr%2C%20D.%20Dardyk%2C%20G.%20Chen%2C%20J.B.%20Native%20client%3A%20A%20sandbox%20for%20portable%2C%20untrusted%20x86%20native%20code%202009) [GScholar](https://scholar.google.co.uk/scholar?q=Yee%2C%20B.%20Sehr%2C%20D.%20Dardyk%2C%20G.%20Chen%2C%20J.B.%20Native%20client%3A%20A%20sandbox%20for%20portable%2C%20untrusted%20x86%20native%20code%202009) [Scite](https://api.scholarcy.com/scite_url?query=Yee%2C%20B.%20Sehr%2C%20D.%20Dardyk%2C%20G.%20Chen%2C%20J.B.%20Native%20client%3A%20A%20sandbox%20for%20portable%2C%20untrusted%20x86%20native%20code%202009)

[^61]: T. Zhang, W. Shen, D. Lee, C. Jung, A. M. Azab, and R. Wang. Pex: A permission check analysis framework for linux kernel. In Proceedings of the 28th USENIX Security Symposium (Security), 2019. [[Zhang_et+al_APermissionCheckAnalysis_2019]] [OA](https://api.scholarcy.com/oa_version?query=Zhang%2C%20T.%20Shen%2C%20W.%20Lee%2C%20D.%20Jung%2C%20C.%20Pex%3A%20A%20permission%20check%20analysis%20framework%20for%20linux%20kernel%202019) [GScholar](https://scholar.google.co.uk/scholar?q=Zhang%2C%20T.%20Shen%2C%20W.%20Lee%2C%20D.%20Jung%2C%20C.%20Pex%3A%20A%20permission%20check%20analysis%20framework%20for%20linux%20kernel%202019) [Scite](https://api.scholarcy.com/scite_url?query=Zhang%2C%20T.%20Shen%2C%20W.%20Lee%2C%20D.%20Jung%2C%20C.%20Pex%3A%20A%20permission%20check%20analysis%20framework%20for%20linux%20kernel%202019)

[^62]: Z. Zhang, Y. Cheng, S. Nepal, D. Liu, Q. Shen, and F. A. Rabhi. KASR: A reliable and practical approach to attack surface reduction of commodity OS kernels. In Proceedings of the 21st International Symposium on Research in Attacks, Intrusions, and Defenses (RAID), 2018. [[Zhang_et+al_KasrAReliablePracticalApproach_2018]] [OA](https://api.scholarcy.com/oa_version?query=Zhang%2C%20Z.%20Cheng%2C%20Y.%20Nepal%2C%20S.%20Liu%2C%20D.%20KASR%3A%20A%20reliable%20and%20practical%20approach%20to%20attack%20surface%20reduction%20of%20commodity%20OS%20kernels%202018) [GScholar](https://scholar.google.co.uk/scholar?q=Zhang%2C%20Z.%20Cheng%2C%20Y.%20Nepal%2C%20S.%20Liu%2C%20D.%20KASR%3A%20A%20reliable%20and%20practical%20approach%20to%20attack%20surface%20reduction%20of%20commodity%20OS%20kernels%202018) [Scite](https://api.scholarcy.com/scite_url?query=Zhang%2C%20Z.%20Cheng%2C%20Y.%20Nepal%2C%20S.%20Liu%2C%20D.%20KASR%3A%20A%20reliable%20and%20practical%20approach%20to%20attack%20surface%20reduction%20of%20commodity%20OS%20kernels%202018)

[^63]: Z. Zhou, M. K. Reiter, and Y. Zhang. A software approach to defeating side channels in last-level caches. In Proceedings of the 23rd ACM Conference on Computer and Communications Security (CCS), 2016. [[Zhou_et+al_SoftwareApproachDefeatingSideChannels_2016]] [OA](https://api.scholarcy.com/oa_version?query=Zhou%2C%20Z.%20Reiter%2C%20M.K.%20Zhang%2C%20Y.%20A%20software%20approach%20to%20defeating%20side%20channels%20in%20last-level%20caches%202016) [GScholar](https://scholar.google.co.uk/scholar?q=Zhou%2C%20Z.%20Reiter%2C%20M.K.%20Zhang%2C%20Y.%20A%20software%20approach%20to%20defeating%20side%20channels%20in%20last-level%20caches%202016) [Scite](https://api.scholarcy.com/scite_url?query=Zhou%2C%20Z.%20Reiter%2C%20M.K.%20Zhang%2C%20Y.%20A%20software%20approach%20to%20defeating%20side%20channels%20in%20last-level%20caches%202016)

[^64]: P. Zieris and J. Horsch. A leak-resilient dual stack scheme for backward-edge control-flow integrity. In Proceedings of the 2018 on Asia Conference on Computer and Communications Security, pages 369–380, 2018.  [[Zieris_LeakresilientDualStackSchemeBackwardedge_2018]] [OA](https://api.scholarcy.com/oa_version?query=Zieris%2C%20P.%20Horsch%2C%20J.%20A%20leak-resilient%20dual%20stack%20scheme%20for%20backward-edge%20control-flow%20integrity%202018) [GScholar](https://scholar.google.co.uk/scholar?q=Zieris%2C%20P.%20Horsch%2C%20J.%20A%20leak-resilient%20dual%20stack%20scheme%20for%20backward-edge%20control-flow%20integrity%202018) [Scite](https://api.scholarcy.com/scite_url?query=Zieris%2C%20P.%20Horsch%2C%20J.%20A%20leak-resilient%20dual%20stack%20scheme%20for%20backward-edge%20control-flow%20integrity%202018)

