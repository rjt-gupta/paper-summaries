[[University of Waterloo_PacstackAuthenticatedCallStack_2020]]

# [PACStack: an Authenticated Call Stack]()

## [[Hans Liljestrand University of Waterloo]]; [[Canada hans@liljestrand.dev]]

### 2020

## Abstract
A popular run-time attack technique is to compromise the control-flow integrity of a program by modifying function return addresses on the stack. So far, shadow stacks have proven to be essential for comprehensively preventing return address manipulation. Shadow stacks record return addresses in integrity-protected memory secured with hardware-assistance or software access control. Software shadow stacks incur high overheads or trade off security for efficiency. Hardwareassisted shadow stacks are efficient and secure, but require the deployment of special-purpose hardware.

## Key concepts
#return_address; #link_register; #control_flow_integrity; #shadow_stack; #stack_frame; #message_authentication_codes; #run_time; #return_oriented_programming; #intermediate_representation; #program_counter; #arm_architecture; #address_space_layout_randomization; #control_flow_graph

## Quote
> With PACStack, we demonstrate how the general-purpose security pointer authentication security mechanism can realize our design, without requiring additional hardware support or compromising security


## Key points
- Traditional code-injection attacks are ineffective in the presence of W⊕X policies that prevent the modification of executable memory [^49]
- We propose a new approach, authenticated call stack (ACS), providing security comparable to hardwareassisted shadow stacks, with minimal overhead and without requiring new hardware-protected memory
- ACS protects these values by computing a series of chained authentication tokens authi, i ∈ [0, n] that cryptographically bind the last authn to all return addresses reti, i ∈ [0, n − 1] stored on the stack (Figure 2)
- Callee-saved registers and link register (LR) are stored in struct cpu_context6 which belongs to the in-kernel task structure and cannot be accessed by user space
- Based on prior evaluations of the QARMA cipher [^7], which is used as the underlying cryptographic primitive in reference implementations of pointer authentication (PA) [^45], Liljestrand et al estimate that the pointer authentication codes (PACs) calculations incur an average overhead of four cycles on a 1.2GHz CPU [^35]
- With PACStack, we demonstrate how the general-purpose security PA security mechanism can realize our design, without requiring additional hardware support or compromising security

## Synopsis

### 1 Introduction
Traditional code-injection attacks are ineffective in the presence of W⊕X policies that prevent the modification of executable memory [^49].
To prevent ROP, return addresses must be protected when stored in memory.
The most powerful protection against ROP is using an integrity-protected shadow stack that maintains a secure reference copy of each return address [^1].
Only hardware-assisted schemes, such as Intel CET [^29], achieve negligible overhead without trading off security.
We propose a new approach, authenticated call stack (ACS), providing security comparable to hardwareassisted shadow stacks, with minimal overhead and without requiring new hardware-protected memory.
ACS, a new approach for precise verification of function return addresses by chaining MACs (Section 4).
PACStack, an LLVM-based realization of ACS using ARM PA without requiring additional hardware (Section 5).
PACStack and associated evaluation code is available as open source at https://pacstack.github.io

### 2.1 ROP on ARM
In ROP, the adversary exploits a memory vulnerability to manipulate return addresses stored on the stack, thereby altering the program’s backward-edge control flow.
ROP allows Turing-complete attacks by chaining together multiple gadgets, i.e., adversary-chosen sequences of pre-existing program instructions that together perform the desired operations.
ARM architectures use the link register (LR) to hold the current function’s return address.
LR is automatically set by the branch with link or branch with link to register instructions that are used to implement regular and indirect function calls.
Because LR is overwritten on call, non-leaf functions must store the return address onto the stack.
This opens up the possibility of ROP on ARM [^30]

### 2.2 ARM Pointer Authentication
The ARMv8.3-A PA extension supports calculating and verifying pointer authentication codes (PACs) [^4].
PA is at present deployed in the Apple A12, A13, S4, and S5 systems-on-chip (SoCs) and is going to be available in all upcoming ARMv8.3A and later SoCs. A pac instruction calculates a keyed tweakable MAC, HK(AP, M), over the address AP of a pointer P using a 64-bit modifier M as the tweak.
The resulting authentication token, referred to as a PAC, is embedded into the unused high-order bits of P.
It can be verified using an aut instruction that recalculates HK(AP, M), and compares the result to P’s PAC.
PA does not cause a fault on verification failure; instead, it strips the PAC from the pointer P and flips one of the high-order bits such that P becomes invalid.
PA does not access memory directly, the LR value is stored ( ) and loaded ( ) conventionally

### 2.2.1 PA-based return address protection
An authenticated return address is computed with paciasp ( in Listing 1) and verified with retaa ( ).
These instructions use the instruction key A and the value of stack pointer (SP) as the modifier.
The -mbranch-protection feature and other prior PAbased solutions are vulnerable to reuse attacks where an adversary replaces a valid authenticated return address with another authenticated return address previously read from the process’ memory.
For a reused PAC to pass verification, both the original and replacement PAC must have been computed using the same PA key and modifier.
This applies to any PA scheme, authenticated return addresses.
Reuse attacks can be mitigated, but not completely prevented, by further narrowing the scope of modifier values [^35]

### 3 Adversary model and requirements
We consider a powerful adversary, A, with arbitrary control of process memory but restricted by a W⊕X policy that prevents modification of code pages.
This adversary model is consistent with prior work on run-time attacks [^49].
We make the following assumptions about the system: A1 A W⊕X policy protects code memory pages from modification by non-privileged processes.
We assume that indirect function-calls always target the beginning of a function and that indirect jumps to arbitrary addresses is infeasible.
A minimal PA scheme using a constant (e.g., 0x0) modifier fulfills this assumption
This adversary model allows A to modify any pointer in data memory pages.
As in prior work on CFI, we do not consider non-control data attacks [^12], such as data-oriented programming (DOP) [^27]

### 4 Design: authenticated call stack
We present our general design for an authenticated call stack (ACS). In Section 5, we present our implementation that efficiently realizes ACS using ARM PA.
Our key idea is to provide a modifier for the return address by cryptographically binding it to all previous return addresses in the call stack.
ACS protects these values by computing a series of chained authentication tokens authi, i ∈ [0, n] that cryptographically bind the last authn to all return addresses reti, i ∈ [0, n − 1] stored on the stack (Figure 2).
The MAC key and the last authentication token authn must be stored securely to ensure that previous auth tokens and return addresses can be correctly verified when unwinding the call stack (R1).
One or both of the loaded values have been corrupted (R1)
Otherwise, they are valid—i.e., authi−1 = authi−1 and reti = reti—in which case authi is replaced with the verified authi−1 in the secure register before the function returns to reti.

### 4.1 Securing the authentication token
The current authenticated return address aretn, is secured by keeping it exclusively in a CPU register which we call the chain register (CR).
Combined with coarse-grained forward-edge CFI (Assumption A2), it ensures that: 1) immediately after function return, the aretn in CR is valid, 2) at function entry the aretn−1 stored in CR is valid, and 3) CR is always used as or set to a valid aret.
This ensures that token updates are done securely, and that the ACS instrumentation cannot be bypassed or used to generate arbitrary authenticated return addresses

### 4.2 Mitigating hash-collisions
Though aretn is protected by hardware, the size b of the authentication token auth can be limited by the implementation.
Can attempt a new guess against another sibling process without resetting the key
In this scenario, 2b−1 guesses on average are enough to obtain a modifier with respect to which some combination of pointer and authentication token is valid.
2b−1 guesses on average are enough to obtain a modifier with respect to which some combination of pointer and authentication token is valid
Since this modifier becomes the authenticated return address, the process can be repeated to use the injected address.
If a child process never returns to inherited stack frames, reseeding any new auth tokens beyond the point of the fork is sufficient.
If the child process returns to inherited stack frames, the ACS must be re-seeded starting from auth0 by rewriting any auth tokens in pre-existing stack frames; similar to some stack canary re-randomization schemes [^25], [^43]

### 4.3 Mitigating brute-force guessing
A brute force attack where A guesses an auth token succeeds with probability p for a b-bit auth after log(1− p) log(1−2−b ).
Callee-saved registers, as well as the stack pointer SP, and the return address are stored in the given jmp_buf buffer.
Calling longjmp using an expired buffer, i.e., after the corresponding setjmp caller has returned, results in undefined behavior.
Because jmp_buf stores the last authenticated token, ACS needs a mechanism to ensure its integrity when using setjmp and longjmp.
The stored authi is bound to the corresponding authi−1 on the setjmp caller’s stack.
This ensures that longjmp always restores a valid ACS state.
Since longjmp explicitly allows jumping to prior states, ACS cannot ensure that the target is the intended one, i.e., A could substitute the correct jmp_buf with another.

### 5 Implementation
We present PACStack, an ACS realization using ARMv8.3A PA. PACStack is based on LLVM 9.0 and integrated into the 64-bit ARM backend.
The current authenticated return address is securely stored in CR.
PACStack uses the pacia and autia instructions to efficiently calculate and verify authenticated return addresses (Listing 2,  and ).
Listing 2: At function entry, PACStack stores areti−1 on the stack () and generates a new areti () which is retained in.
Areti−1 is loaded from the stack () and verified against areti ().
To maintain compatibility (R3), PACStack does not modify the frame record () and instead stores areti−1 in a separate stack slot ().
This allows, for instance, debuggers to backtrace the call-stack without knowledge of PACStack.
PACStack never loads reti from the frame record; it always uses areti which is securely stored in CR

### 5.1 Securing the authentication token
PACStack uses the ARM general purpose register X28 as CR for storing the last authentication token.
X28 is a callee-saved register, and so, any function that uses it must restore the old value before return.
By using X28 as CR, PACStack libraries or code can be transparently mixed with uninstrumented code (R3).
We discuss the security implications of mixing instrumented and uninstrumented code in Section 9.2

### 5.2 Mitigating hash collisions
To prevent A from identifying PAC collisions that can be reused to violate the integrity of the call stack, PACStack masks all authentication tokens values before storing them on the stack.
By using pacia we efficiently obtain a pseudo-random value that can be directly applied to the authentication token part of aret using only an exclusive-or instruction
Because this construction uses the same key to generate both authentication tokens and masks, A must not obtain an areti for a reti = 0x0 and any existing areti−1.
Listing 4: PACStack redirects setjmp calls to our setjmp_wrapper 4 which binds the return address aretb to areti and the SP value before it is stored in jmp_buf.
This approach to masking requires two additional PAC calculations for each function activation.
A cannot generate aretb for arbitrary values and cannot inject them in jmp_buf. #r, #a and #s are the offsets to retb, CR, and reti within jmp_buf

### 5.4 Multi-threading
The values of ARMv8-A general purpose registers are stored in memory when entering EL1 from EL0, for example during context switches and system calls.
This must not allow A to modify the aret values or read the mask, which are both exclusively in either CR or LR during execution (Listings 2 and 3), but must be stored in memory during the context switch.
Callee-saved registers and LR are stored in struct cpu_context which belongs to the in-kernel task structure and cannot be accessed by user space.
The CR and LR values of a non-executing task are securely stored within the kernel, beyond the reach of other processes or other threads within the same process.
No kernel modifications are needed to securely apply PACStack to multi-threaded applications

### 5.3 Irregular stack unwinding
PACStack binds jmp_buf buffers to the areti at the time of setjmp call by replacing the setjmp return address retb with its authenticated counterpart aretb before setjmp stores it to the jmp_buf (Section 4.4).
The libc implementation is not modified; instead setjmp / longjmp calls are replaced with the wrapper functions in Listings 4 and 5.
The setjmp_wrapper (Listing 4) replaces the return address in LR with aretb and executes setjmp, which stores it in the buffer.
The longjmp_wrapper (Listing 5) retrieves aretb, areti, and the SP values from jmp_buf, verifies their values and writes retb into jmp_buf before executing longjmp

### 6 Security evaluation
We address three questions : 1) Is PAC reuse a realistic concern in prior PA-based schemes?
2) Is the ACS scheme cryptographically secure?
3) Do ACS’s guarantees hold when instantiated as PACStack?.
Listing 6: The -mbranch-protection implementation (Section 2.2.1) computes the PAC for return addresses using the SP value at function entry.
Both invocations in func (Lines 7 and 9) will use the same SP value as modifier.
A can reuse the signed address from Line 7 to make the function invocation at Line 9 return to Line 8

### 6.1 Reuse attacks on PA
Reuse attack on PA-based schemes are possible when the modifier is calculated with known or predictably repeating values.
Using the SP can mitigate reuse attacks (Section 2.2.1).
-mbranch-protection generates the PAC immediately on function entry, before modifying the SP value to allocate stack space.
All functions called from within a code segment use the same modifier unless there are dynamic stack allocations.
Because the stack is typically aligned to 8 bytes, the SP value will often repeat.
A less than 1s test execution of a SPEC CPU 2017 benchmark (538.imagick_r) already shows multiple collisions, with 5349 distinct (LR,SP) pairs, but only 914 unique SP values.
Listing 6 shows a minimal example where all called functions will end up using the same modifier and have interchangeable signed return addresses

### 6.2 ACS security
AG-Load: Violate the integrity of the call stack such that the LR register is loaded with aretB from AG-Jump rather than the correct authenticated return address aretA
This requires two returns: one from a ‘loader’ function to load A’s aretB into LR, and another from C to the return address retB contained in aretB.
In the analysis below we assume that programs that share the same PA keys between multiple processes or threads employ the mitigation strategy against brute-force attacks described in Section 4.3
This assumption and the design of ACS ensure that there is no authentication oracle available: the only way to test whether an auth token is valid with respect to some address and modifier is to attempt to return using the address and token, triggering a crash if the token is incorrect.
Violating control-flow integrity while still traversing the call graph is easier because this allows A to harvest auth tokens and search for collisions; violations that do not follow the call graph are more difficult because they require that A make one or more guesses, risking a crash

### 6.2.1 Violations that follow the call graph
As A can harvest authenticated return pointers when they are written to the stack, the short auth tokens mean that in the absence of masking an attacker can violate the integrity of the call stack by finding collisions in HK(·, ·).
In order to achieve goal AG-Load, A must find two authenticated return addresses aretA and aretB, such that i) they are both returned to by a function C, ii) that C contains a call-site to the loader function with a corresponding return address retC, and iii) such that.
A can obtain as many auth tokens with retC as a pointer as there are distinct execution paths leading to C.
The number of such paths will explode combinatorially as the complexity of the program increases, and cycles in the call graph—as occur in Figure 4— make the number of paths essentially infinite, limited only by available stack space.

### C Correct control flow loader
In order to successfully mount the above attack, A must find two colliding auth tokens and perform the substitution.
A can keep collecting auth tokens until they find two that collide; since these are both valid pointers, A will always succeed once this occurs, .
It is impossible to identify a collision with a probability greater than by random selection.
This means that A will succeed in the attack above with a probability of 2−b.
We give a detailed proof in Appendix A
This means that A can use this attack to traverse the program’s call graph, but cannot jump to an address that is not a valid return address for function C

### 6.2.2 Violations that leave the call graph
In this case, the path from B to C has not been traversed, and the instrumentation has never before computed the auth token HK(retC, aretB).
A’s probability of achieving goal AG-Jump depends on whether retB is the return address of a valid call-site.
If it is, A can obtain a valid authenticated return pointer for that location in the same way as in Section 6.2.1.
If retB has never been used as a return address, no auth token has ever been generated for that pointer and AG-Jump is achieved with probability at most P[AG-Jump] = 2−b, independent of.

### 6.3 Run-time attack resistance of PACStack
The former is achieved by storing aretn in CR, which is reserved for this purpose, not used by regular code, and inaccessible to A (Section 5.1)
The latter is maintained as the mask is re-generated each time it is needed and cleared after use (Section 5.2).
By requiring coarse-grained forward-edge CFI (Assumption A2), PACStack ensures that auth token calculations and masking are executed atomically and cannot be used to manipulate reti, areti−1 or the mask during the function prologue and epilogue.
This holds when the forward-edge CFI is susceptible to control-flow bending (Section 3)

### 6.3.1 Tail calls and signing gadgets
A recent discovery by Google Project Zero [^8] shows that PA schemes can be vulnerable to an attack whereby specific code sequences can be used as gadgets to generate PACs for arbitrary pointers.
Recall that on PAC verification failure an aut instruction removes the PAC, but corrupts a well-known high-order bit such that the pointer becomes invalid.
If a pac instruction adds a PAC to a pointer P with corrupt high-order bits, it treats the high-order bits as though they were correct when calculating the new PAC, and flips a well-known bit p of the PAC if any high-order bit was corrupt
This means that instruction sequences such as the one shown in Listing 7, consisting of an aut instruction followed by a pac instruction, can be used generate a valid PAC for a pointer even if the original pointer is not valid to begin with.
An invalid input pointer () after aut ( ) can be re-signed ( ), resulting in an output PAC with only a single bit-flip.
This could be exploited to generate valid PACs for arbitrary pointers.
A architecture will preclude such attacks in general [^3]

### 6.3.2 Sigreturn-oriented programming
Sigreturn-oriented programming [^9] is a exploitation technique in UNIX-like operating systems, including Linux, that abuses the signal frame to take complete control of a process’s execution state, i.e., the values of general purpose registers, SP, program counter (PC), status flags, etc.
When the kernel delivers a signal, it suspends the process and changes the user-space processor context such that the appropriate signal handler is executed with the right arguments.
When the signal handler returns, the original user-space processor context is restored.
In a sigreturn attack A sets up a fake signal frame and initiates a return from a signal that the kernel never delivered.
A program returns from the handler using a sigreturn system call that reads a signal frame from the process stack.
Bosman and Bos [^9] propose placing keyed signal canaries in the signal frame that are validated by the kernel before performing a sigreturn, or to keep a counter of the number of currently executing signal handlers.
We discuss a potential general solution against sigreturn attacks that utilizes the ACS construction in Appendix B

### 7 Performance Evaluation
The only publicly available PA-enabled SoCs are the Apple A12, A13, S4, and S5, none of which support PA for 3rd party code at the time of writing.
Because the FVP runs the v4.14 kernel, we have used PA RFC patches modified to support all PA keys.
The FVP is not cycle-accurate and executes all instructions in one master cycle; it cannot be used for performance evaluation.
Based on prior evaluations of the QARMA cipher [^7], which is used as the underlying cryptographic primitive in reference implementations of PA [^45], Liljestrand et al estimate that the PAC calculations incur an average overhead of four cycles on a 1.2GHz CPU [^35].
We employ the PA-analogue introduced by Liljestrand et al to estimate the run-time overhead of PACStack

### 7.1 SPEC CPU 2017
To guarantee exclusive access to the hardware, we used Amazon EC2 a1.metal9,10instances, each with 16 64-bit ARMv8.2-A cores.
As these CPUs do not support PA, we instrumented benchmarks with the PAanalogue.
We measured PACStack by instrumenting all function entry and exit points, excluding leaf functions that do not spill LR or the CR.
Due to compatibility issues with ShadowCallStack and -mbranch-protection, we limit our comparison to the C benchmarks.
We see little effect on the performance of 519.lbm_r
Based on these results, we expect the overhead for both PACStack configurations to be a) comparable to ShadowCallStack, and b) negligible on PA-capable hardware

### 7.2 Real-world evaluation
We evaluated the efficacy of PACStack in a real-world setting using a SSL/TLS transactions per second (SSL TPS) test on the NGINX11 open source web server software.
SSL TPS measures a web server’s capacity to create new SSL/TLS connections back to clients.
Clients send a series of HTTPS requests, each on a new connection.
We configured wrk in the same way as in a test on NGINX performance conducted by F5 Networks..
We repeated the test with four and eight NGINX worker processes instrumented with PACStack and PACStack-nomask, and compared the results with uninstrumented baseline performance.
In both configurations we instrumented NGINX’s dependencies (OpenSSL, pcre and zlib libraries).
We summarize the results, showing a 4–7% overhead for PACStack-nomask and 6–13% overhead for PACStack
These results are consistent with the performance overheads measures for SPEC CPU 2017 (Section 7.1)

### 7.3 Compatibility testing using ConFIRM
ConFIRM is a set small micro-benchmarking suite designed to test compatibility and relevance of CFI solutions [^52].
The suite is designed to test various corner-cases—e.g., function pointers, setjmp/longjmp and exception handling—that often cause compatibility issues for CFI solutions.
ConFIRM is designed for x86-based architectures and includes some tests that are exclusive to the Microsoft Windows operating system.
Of the 18 64-bit Linux tests 11 compiled and worked on AArch; these included virtual and indirect function calls, setjmp/longjmp, calling conventions, tail calls and load-time dynamic linking.
We ran these benchmarks on the FVP and confirmed that the tests passed with or without PACStack.

### 8 Related Work
Control-flow hijacking have been known for more than two decades [^48]. Most current CFI solutions are stateless: they validate each control-flow transfer in isolation without distinguishing among different paths in the control-flow graph (CFG).
This increases the complexity and run-time of the shadow stack instrumentation placed in the function epilogue, and sacrifices precision, e.g., it allows A to redirect longjmp to any previously active call site
This can be avoided by storing and validating both the return address and stack pointer [^15], [^40], [^50].
MoCFI [^18] is a softwarebased CFI approach targeting ARM application processors used in smartphones
It uses a combination of a shadow stack, static analysis and run-time heuristics to determine the set of valid targets for control-flow transfers, but suffers from the same drawbacks that plague traditional shadow stack schemes.
BTI constitutes one way to meet the PACStack pre-requisite of coarse-grained CFI (Section 3)

### 9.1 Support for software exceptions
The setjmp / longjmp interface has traditionally been used to provide exception-like functionality in C.
A can modify jmp_buf to contain the previously used aretb and SPb, but must modify the stack-frame at SPb, such that it contains the prior areti.
This allows a controlflow transfer to a previously valid setjmp return site and SP value.
To prevent reuse of expired jmp_buf buffers, longjmp can be rewound step-by-step, i.e., conceptually performing returns until the correct stack-frame is reached.
We plan to extend PACStack support to LLVM libunwind14 – it does frame-by-frame unwinding of the call stack.
With PACStack support in libunwind, we will be able to secure both setjmp / longjmp and support C++ exception handling

### 9.2 Interoperability with unprotected code
PACStack-protected applications may need to interoperate with unprotected shared libraries.
On the other, unprotected applications may need to interoperate with PACStack-protected shared libraries.
The latter scenario is relevant for deployment.
The deployment of PACStack, or any other run-time protection mechanism, is likely to be driven by OEMs that enable specific protection schemes for the operating system and system applications.
OEMs are not in control of native code deployed as part of applications
It should be possible for one version of the shared libraries shipped with the operating system to remain interoperable with both PACStack-protected, and unprotected apps.
In Section 5.1 we explain how the use of callee-saved registers allows PACStack to remain interoperable with unprotected code.

### 10 Conclusion
ACS achieves security on-par with hardware-assisted shadow stacks (Section 6).
With PACStack, we demonstrate how the general-purpose security PA security mechanism can realize our design, without requiring additional hardware support or compromising security.
Other general-purpose primitives like memory tagging and branch target indicators are being rolled out.
Creative uses of such primitives hold the promise of significantly improving software protection

### A Security proofs
In Section 6.2, we gave an informal analysis of the security of ACS; here we give a more detailed proof of security, and in particular prove that authentication token masking prevents.
Assuming a key-length of λ for HK(·, ·), and given access to q masked authentication tokens, A can identify a pair of inputs (x, y) and (x, y ) whose corresponding unmasked authentication tokens collide with advantage at most 2AdvAPAC-Distinguish(1λ, H, q).
We begin with a collision-game GAPAC-Collision(1λ, H, q), shown in Figure 6 in which the adversary is given oracle access to the authentication token generator and asked to provide values x, y, y such that HK(x, y) = HK(x, y ).
The third game is a semantic security game for the onetime pad, where A is given 2VA_SIZE encryptions of S1 and asked to distinguish between S1 and a random string.

### B Mitigation of sigreturn attacks
Was already executing a signal handler, and the kernel already has a reference copy of asigretn−1 on record, it stores asigretn−1 in the new signal frame and overwrites the secure copy with asigretn.
Otherwise the kernel assumes a return to a nested signal handler, and retrieves sigretn and asigretn−1 from the signal frame, validates them by calculating asigretn = HK(sigretn, asigretn−1) and comparing the result against the stored asigretn reference value.
If successful the kernel replaces asigretn with asigretn−1 in the secure kernel store and performs the signal return to sigretn.
For general protection against sigreturn attacks corrupting any register stored in the signal frame, all register values could be included in the asigret calculation using the pacga instruction and validated at the time of sigreturn

##  Confirmation of earlier findings
- This adversary model is ^^consistent with prior work on run-time attacks [^49]. We limit A to user space^^; thus A cannot read or modify kernelmanaged registers such as the PA keys

## Counterpoint to earlier claims
- In contrast to PACStack, these approaches cannot prevent reuse attacks (See Section 6.1). Independently to ^^our work, Li et al [^34] propose a chain structure to protect return addresses but do not prevent the attacker from exploiting MAC collisions^^, and require custom hardware to realize their solution

## Data and code
- https://github.com/pacstack/pacstack-wrappers


## References
[^1]: Martín Abadi et al. Control-flow integrity principles, implementations, and applications. ACM Trans. Inf. Syst. Secur., 13(1):4:1–4:40, November 2009. [[Abadi_ControlflowIntegrityPrinciplesImplementationsApplications_2009]] [OA](https://api.scholarcy.com/oa_version?query=Abadi%2C%20Mart%C3%ADn%20Control-flow%20integrity%20principles%2C%20implementations%2C%20and%20applications%202009-11) [GScholar](https://scholar.google.co.uk/scholar?q=Abadi%2C%20Mart%C3%ADn%20Control-flow%20integrity%20principles%2C%20implementations%2C%20and%20applications%202009-11) [Scite](https://api.scholarcy.com/scite_url?query=Abadi%2C%20Mart%C3%ADn%20Control-flow%20integrity%20principles%2C%20implementations%2C%20and%20applications%202009-11)

[^2]: ARM Ltd. Fast models version 11.4 reference manual. https://developer.arm.com/documentation/100964/1104-00/, 2018. processors/b/processors-ip-blog/posts/armarchitecture-developments-armv8-6-a, 2019. [[Ltd_FastModelsVersion114Reference_2019]] [OA](https://developer.arm.com/documentation/100964/1104-00/)  

[^4]: ARM Ltd. ARM architecture reference manual (ARM DDI 0487F.c). https://developer.arm.com/documentation/ddi0487/fc, 2020. [[Ltd_ArmArchitectureReferenceManualarm_2020]] [OA](https://developer.arm.com/documentation/ddi0487/fc)  

[^5]: ARM Ltd. Armv8-M architecture reference manual (ARM DDI 0553B.l). https://developer.arm.com/documentation/ddi0553/bl/, 2020. [[Ltd_Armv8mArchitectureReferenceManualarm_2020]] [OA](https://developer.arm.com/documentation/ddi0553/bl/)  

[^6]: Sergei Arnautov and Christof Fetzer. ControlFreak: Signature chaining to counter control flow attacks. In Proc. IEEE SRDS ’15, pages 84–93, 2015. [[Arnautov_ControlfreakSignatureChainingCounterControl_2015]] [OA](https://api.scholarcy.com/oa_version?query=Arnautov%2C%20Sergei%20Fetzer%2C%20Christof%20ControlFreak%3A%20Signature%20chaining%20to%20counter%20control%20flow%20attacks%202015) [GScholar](https://scholar.google.co.uk/scholar?q=Arnautov%2C%20Sergei%20Fetzer%2C%20Christof%20ControlFreak%3A%20Signature%20chaining%20to%20counter%20control%20flow%20attacks%202015) [Scite](https://api.scholarcy.com/scite_url?query=Arnautov%2C%20Sergei%20Fetzer%2C%20Christof%20ControlFreak%3A%20Signature%20chaining%20to%20counter%20control%20flow%20attacks%202015)

[^7]: Roberto Avanzi. The QARMA block cipher family. almost MDS matrices over rings with zero divisors, nearly symmetric even-mansour constructions with noninvolutory central rounds, and search heuristics for lowlatency s-boxes. IACR Trans. Symmetric Cryptol., 2017(1):4–44, 2017. [[Avanzi_QarmaBlockCipherFamilyAlmost_2017]] [OA](https://api.scholarcy.com/oa_version?query=Avanzi%2C%20Roberto%20The%20QARMA%20block%20cipher%20family.%20almost%20MDS%20matrices%20over%20rings%20with%20zero%20divisors%2C%20nearly%20symmetric%20even-mansour%20constructions%20with%20noninvolutory%20central%20rounds%2C%20and%20search%20heuristics%20for%20lowlatency%20s-boxes%202017) [GScholar](https://scholar.google.co.uk/scholar?q=Avanzi%2C%20Roberto%20The%20QARMA%20block%20cipher%20family.%20almost%20MDS%20matrices%20over%20rings%20with%20zero%20divisors%2C%20nearly%20symmetric%20even-mansour%20constructions%20with%20noninvolutory%20central%20rounds%2C%20and%20search%20heuristics%20for%20lowlatency%20s-boxes%202017) [Scite](https://api.scholarcy.com/scite_url?query=Avanzi%2C%20Roberto%20The%20QARMA%20block%20cipher%20family.%20almost%20MDS%20matrices%20over%20rings%20with%20zero%20divisors%2C%20nearly%20symmetric%20even-mansour%20constructions%20with%20noninvolutory%20central%20rounds%2C%20and%20search%20heuristics%20for%20lowlatency%20s-boxes%202017)

[^8]: Brandon Azad. Google Project Zero: Examining pointer authentication on the iPhone XS. https://googleprojectzero.blogspot.com/2019/02/examining-pointer-authentication-on.html, 2019. [[Azad_GoogleProjectZeroExaminingPointer_2019]] [OA](https://googleprojectzero.blogspot.com/2019/02/examining-pointer-authentication-on.html)  

[^9]: Erik Bosman and Herbert Bos. Framing signals - a return to portable shellcode. In Proc. IEEE S&P ’14, pages 243–258, 2014. [[Bosman_FramingSignalsReturnPortable_2014]] [OA](https://api.scholarcy.com/oa_version?query=Bosman%2C%20Erik%20Bos%2C%20Herbert%20Framing%20signals%20-%20a%20return%20to%20portable%20shellcode%202014) [GScholar](https://scholar.google.co.uk/scholar?q=Bosman%2C%20Erik%20Bos%2C%20Herbert%20Framing%20signals%20-%20a%20return%20to%20portable%20shellcode%202014) [Scite](https://api.scholarcy.com/scite_url?query=Bosman%2C%20Erik%20Bos%2C%20Herbert%20Framing%20signals%20-%20a%20return%20to%20portable%20shellcode%202014)

[^10]: Nathan Burow, Xingping Zhang, and Mathias Payer. SoK: Shining light on shadow stacks. In Proc. IEEE S&P ’19, pages 985–999, 2019. [[Burow_et+al_SokShiningLightShadowStacks_2019]] [OA](https://api.scholarcy.com/oa_version?query=Burow%2C%20Nathan%20Zhang%2C%20Xingping%20Payer%2C%20Mathias%20SoK%3A%20Shining%20light%20on%20shadow%20stacks%202019) [GScholar](https://scholar.google.co.uk/scholar?q=Burow%2C%20Nathan%20Zhang%2C%20Xingping%20Payer%2C%20Mathias%20SoK%3A%20Shining%20light%20on%20shadow%20stacks%202019) [Scite](https://api.scholarcy.com/scite_url?query=Burow%2C%20Nathan%20Zhang%2C%20Xingping%20Payer%2C%20Mathias%20SoK%3A%20Shining%20light%20on%20shadow%20stacks%202019)

[^11]: Nicolas Carlini et al. Control-flow bending: On the effectiveness of control-flow integrity. In Proc. USENIX Security ’15, pages 161–176, 2015. [[Carlini_ControlflowBendingOnEffectivenessControlflow_2015]] [OA](https://api.scholarcy.com/oa_version?query=Carlini%2C%20Nicolas%20Control-flow%20bending%3A%20On%20the%20effectiveness%20of%20control-flow%20integrity%202015) [GScholar](https://scholar.google.co.uk/scholar?q=Carlini%2C%20Nicolas%20Control-flow%20bending%3A%20On%20the%20effectiveness%20of%20control-flow%20integrity%202015) [Scite](https://api.scholarcy.com/scite_url?query=Carlini%2C%20Nicolas%20Control-flow%20bending%3A%20On%20the%20effectiveness%20of%20control-flow%20integrity%202015)

[^12]: Shuo Chen et al. Non-control-data attacks are realistic threats. In Proc. USENIX Security ’05, pages 177–191, 2005. [[Chen_controldataAttacksRealisticThreats_2005]] [OA](https://api.scholarcy.com/oa_version?query=Chen%2C%20Shuo%20Non-control-data%20attacks%20are%20realistic%20threats%202005) [GScholar](https://scholar.google.co.uk/scholar?q=Chen%2C%20Shuo%20Non-control-data%20attacks%20are%20realistic%20threats%202005) [Scite](https://api.scholarcy.com/scite_url?query=Chen%2C%20Shuo%20Non-control-data%20attacks%20are%20realistic%20threats%202005)

[^13]: Tzi-Cker Chiueh and Fu-Hau Hsu. RAD: A compiletime solution to buffer overflow attacks. In Proc. IEEE ICDCS ’01, pages 409–417, 2001. [[Chiueh_RadACompiletimeSolutionBuffer_2001]] [OA](https://api.scholarcy.com/oa_version?query=Chiueh%2C%20Tzi-Cker%20Hsu%2C%20Fu-Hau%20RAD%3A%20A%20compiletime%20solution%20to%20buffer%20overflow%20attacks%202001) [GScholar](https://scholar.google.co.uk/scholar?q=Chiueh%2C%20Tzi-Cker%20Hsu%2C%20Fu-Hau%20RAD%3A%20A%20compiletime%20solution%20to%20buffer%20overflow%20attacks%202001) [Scite](https://api.scholarcy.com/scite_url?query=Chiueh%2C%20Tzi-Cker%20Hsu%2C%20Fu-Hau%20RAD%3A%20A%20compiletime%20solution%20to%20buffer%20overflow%20attacks%202001)

[^14]: Clang 9.0 Documentation. ShadowCallStack. https://releases.llvm.org/9.0/tools/clang/docs/ShadowCallStack.html, 2019. [[Clang_Clang90Documentation_2019]] [OA](https://releases.llvm.org/9.0/tools/clang/docs/ShadowCallStack.html)  [Scite](https://api.scholarcy.com/scite_url?query=Clang%2090%20Documentation%20ShadowCallStack%20httpsreleasesllvmorg90toolsclangdocsShadowCallStackhtml%202019)

[^15]: Marc L. Corliss, E. Christopher Lewis, and Amir Roth. Using DISE to protect return addresses from attack. ARM SIGARCH Comput. Archit. News, 33(1):65–72, 2005. [[Corliss_et+al_UsingDiseProtectReturnAddresses_2005]] [OA](https://api.scholarcy.com/oa_version?query=Corliss%2C%20Marc%20L.%20Lewis%2C%20E.Christopher%20Roth%2C%20Amir%20Using%20DISE%20to%20protect%20return%20addresses%20from%20attack%202005) [GScholar](https://scholar.google.co.uk/scholar?q=Corliss%2C%20Marc%20L.%20Lewis%2C%20E.Christopher%20Roth%2C%20Amir%20Using%20DISE%20to%20protect%20return%20addresses%20from%20attack%202005) [Scite](https://api.scholarcy.com/scite_url?query=Corliss%2C%20Marc%20L.%20Lewis%2C%20E.Christopher%20Roth%2C%20Amir%20Using%20DISE%20to%20protect%20return%20addresses%20from%20attack%202005)

[^16]: Crispin Cowan et al. PointGuard: Protecting pointers from buffer overflow vulnerabilities. In Proc. USENIX Security ’03, pages 91–104, 2003. [[Cowan_PointguardProtectingPointersFromBuffer_2003]] [OA](https://api.scholarcy.com/oa_version?query=Cowan%2C%20Crispin%20PointGuard%3A%20Protecting%20pointers%20from%20buffer%20overflow%20vulnerabilities%202003) [GScholar](https://scholar.google.co.uk/scholar?q=Cowan%2C%20Crispin%20PointGuard%3A%20Protecting%20pointers%20from%20buffer%20overflow%20vulnerabilities%202003) [Scite](https://api.scholarcy.com/scite_url?query=Cowan%2C%20Crispin%20PointGuard%3A%20Protecting%20pointers%20from%20buffer%20overflow%20vulnerabilities%202003)

[^17]: Thurston H.Y. Dang, Petros Maniatis, and David Wagner. The performance cost of shadow stacks and stack canaries. In Proc.ACM ASIA CCS ’15, pages 555–566, 2015. [[Dang_et+al_PerformanceCostShadowStacksStack_2015]] [OA](https://api.scholarcy.com/oa_version?query=Dang%2C%20Thurston%20H.Y.%20Maniatis%2C%20Petros%20Wagner%2C%20David%20The%20performance%20cost%20of%20shadow%20stacks%20and%20stack%20canaries%202015) [GScholar](https://scholar.google.co.uk/scholar?q=Dang%2C%20Thurston%20H.Y.%20Maniatis%2C%20Petros%20Wagner%2C%20David%20The%20performance%20cost%20of%20shadow%20stacks%20and%20stack%20canaries%202015) [Scite](https://api.scholarcy.com/scite_url?query=Dang%2C%20Thurston%20H.Y.%20Maniatis%2C%20Petros%20Wagner%2C%20David%20The%20performance%20cost%20of%20shadow%20stacks%20and%20stack%20canaries%202015)

[^18]: Lucas Davi et al. MoCFI: A framework to mitigate control-flow attacks on smartphones. In Proc. NDSS ’12, 2012. [[Davi_MocfiAFrameworkMitigateControlflow_2012]] [OA](https://api.scholarcy.com/oa_version?query=Davi%2C%20Lucas%20MoCFI%3A%20A%20framework%20to%20mitigate%20control-flow%20attacks%20on%20smartphones%202012) [GScholar](https://scholar.google.co.uk/scholar?q=Davi%2C%20Lucas%20MoCFI%3A%20A%20framework%20to%20mitigate%20control-flow%20attacks%20on%20smartphones%202012) [Scite](https://api.scholarcy.com/scite_url?query=Davi%2C%20Lucas%20MoCFI%3A%20A%20framework%20to%20mitigate%20control-flow%20attacks%20on%20smartphones%202012)

[^19]: Lucas Davi et al. HAFIX: Hardware-assisted flow integrity extension. In Proc. ACM/EDAC/IEEE DAC ’15, pages 74:1–74:6, 2015. [[Davi_HafixHardwareassistedFlowIntegrityExtension_2015]] [OA](https://api.scholarcy.com/oa_version?query=Davi%2C%20Lucas%20HAFIX%3A%20Hardware-assisted%20flow%20integrity%20extension%202015) [GScholar](https://scholar.google.co.uk/scholar?q=Davi%2C%20Lucas%20HAFIX%3A%20Hardware-assisted%20flow%20integrity%20extension%202015) [Scite](https://api.scholarcy.com/scite_url?query=Davi%2C%20Lucas%20HAFIX%3A%20Hardware-assisted%20flow%20integrity%20extension%202015)

[^20]: Ren Ding et al. Efficient protection of path-sensitive control security. In Proc. USENIX Security ’17, pages 131–148, 2017. [[Ding_EfficientProtectionPathsensitiveControlSecurity_2017]] [OA](https://api.scholarcy.com/oa_version?query=Ding%2C%20Ren%20Efficient%20protection%20of%20path-sensitive%20control%20security%202017) [GScholar](https://scholar.google.co.uk/scholar?q=Ding%2C%20Ren%20Efficient%20protection%20of%20path-sensitive%20control%20security%202017) [Scite](https://api.scholarcy.com/scite_url?query=Ding%2C%20Ren%20Efficient%20protection%20of%20path-sensitive%20control%20security%202017)

[^21]: Isaac Evans et al. Missing the point(er): On the effectiveness of code pointer integrity. In Proc. IEEE S&P ’15, pages 781–796, 2015. [[Evans_MissingPointOnEffectivenessCode_2015]] [OA](https://api.scholarcy.com/oa_version?query=Evans%2C%20Isaac%20Missing%20the%20point%28er%29%3A%20On%20the%20effectiveness%20of%20code%20pointer%20integrity%202015) [GScholar](https://scholar.google.co.uk/scholar?q=Evans%2C%20Isaac%20Missing%20the%20point%28er%29%3A%20On%20the%20effectiveness%20of%20code%20pointer%20integrity%202015) [Scite](https://api.scholarcy.com/scite_url?query=Evans%2C%20Isaac%20Missing%20the%20point%28er%29%3A%20On%20the%20effectiveness%20of%20code%20pointer%20integrity%202015)

[^22]: Michael Frantzen and Michael Shuey. StackGhost: Hardware facilitated stack protection. In Proc. USENIX Security ’01, pages 55–66, 2001. [[Frantzen_StackghostHardwareFacilitatedStackProtection_2001]] [OA](https://api.scholarcy.com/oa_version?query=Frantzen%2C%20Michael%20Shuey%2C%20Michael%20StackGhost%3A%20Hardware%20facilitated%20stack%20protection%202001) [GScholar](https://scholar.google.co.uk/scholar?q=Frantzen%2C%20Michael%20Shuey%2C%20Michael%20StackGhost%3A%20Hardware%20facilitated%20stack%20protection%202001) [Scite](https://api.scholarcy.com/scite_url?query=Frantzen%2C%20Michael%20Shuey%2C%20Michael%20StackGhost%3A%20Hardware%20facilitated%20stack%20protection%202001)

[^23]: Jonathon T. Giffin, Somesh Jha, and Barton P. Miller. Detecting manipulated remote call streams. In Proc. USENIX Security ’02, pages 61–79, 2002. [[Giffin_et+al_DetectingManipulatedRemoteCallStreams_2002]] [OA](https://api.scholarcy.com/oa_version?query=Giffin%2C%20Jonathon%20T.%20Jha%2C%20Somesh%20Miller%2C%20Barton%20P.%20Detecting%20manipulated%20remote%20call%20streams%202002) [GScholar](https://scholar.google.co.uk/scholar?q=Giffin%2C%20Jonathon%20T.%20Jha%2C%20Somesh%20Miller%2C%20Barton%20P.%20Detecting%20manipulated%20remote%20call%20streams%202002) [Scite](https://api.scholarcy.com/scite_url?query=Giffin%2C%20Jonathon%20T.%20Jha%2C%20Somesh%20Miller%2C%20Barton%20P.%20Detecting%20manipulated%20remote%20call%20streams%202002)

[^24]: Jonathon T. Giffin, Somesh Jha, and Barton P. Miller. Efficient context-sensitive intrusion detection. In Proc. NDSS ’04, 2004. [[Giffin_et+al_EfficientContextsensitiveIntrusionDetection_2004]] [OA](https://api.scholarcy.com/oa_version?query=Giffin%2C%20Jonathon%20T.%20Jha%2C%20Somesh%20Miller%2C%20Barton%20P.%20Efficient%20context-sensitive%20intrusion%20detection%202004) [GScholar](https://scholar.google.co.uk/scholar?q=Giffin%2C%20Jonathon%20T.%20Jha%2C%20Somesh%20Miller%2C%20Barton%20P.%20Efficient%20context-sensitive%20intrusion%20detection%202004) [Scite](https://api.scholarcy.com/scite_url?query=Giffin%2C%20Jonathon%20T.%20Jha%2C%20Somesh%20Miller%2C%20Barton%20P.%20Efficient%20context-sensitive%20intrusion%20detection%202004)

[^25]: William H. Hawkins, Jason D. Hiser, and Jack W. Davidson. Dynamic canary randomization for improved software security. In Proc. ACM CISRC ’16, pages 9:1–9:7, 2016. [[Hawkins_et+al_DynamicCanaryRandomizationImprovedSoftware_2016]] [OA](https://api.scholarcy.com/oa_version?query=Hawkins%2C%20William%20H.%20Hiser%2C%20Jason%20D.%20Davidson%2C%20Jack%20W.%20Dynamic%20canary%20randomization%20for%20improved%20software%20security%202016) [GScholar](https://scholar.google.co.uk/scholar?q=Hawkins%2C%20William%20H.%20Hiser%2C%20Jason%20D.%20Davidson%2C%20Jack%20W.%20Dynamic%20canary%20randomization%20for%20improved%20software%20security%202016) [Scite](https://api.scholarcy.com/scite_url?query=Hawkins%2C%20William%20H.%20Hiser%2C%20Jason%20D.%20Davidson%2C%20Jack%20W.%20Dynamic%20canary%20randomization%20for%20improved%20software%20security%202016)

[^26]: HORIBA MIRA Ltd. Guidelines for the use of the C language in critical systems, 2004. [[Ltd_GuidelinesCLanguageCriticalSystems_2004]] [OA](https://scholar.google.co.uk/scholar?q=Ltd%2C%20H.O.R.I.B.A.M.I.R.A.%20Guidelines%20for%20the%20use%20of%20the%20C%20language%20in%20critical%20systems%202004) [GScholar](https://scholar.google.co.uk/scholar?q=Ltd%2C%20H.O.R.I.B.A.M.I.R.A.%20Guidelines%20for%20the%20use%20of%20the%20C%20language%20in%20critical%20systems%202004) 

[^27]: Hong Hu et al. Data-oriented programming: On the expressiveness of non-control data attacks. In Proc. IEEE S&P ’16, pages 969–986, 2016. [[Hu_DataorientedProgrammingOnExpressivenesscontrol_2016]] [OA](https://api.scholarcy.com/oa_version?query=Hu%2C%20Hong%20Data-oriented%20programming%3A%20On%20the%20expressiveness%20of%20non-control%20data%20attacks%202016) [GScholar](https://scholar.google.co.uk/scholar?q=Hu%2C%20Hong%20Data-oriented%20programming%3A%20On%20the%20expressiveness%20of%20non-control%20data%20attacks%202016) [Scite](https://api.scholarcy.com/scite_url?query=Hu%2C%20Hong%20Data-oriented%20programming%3A%20On%20the%20expressiveness%20of%20non-control%20data%20attacks%202016)

[^28]: Hong Hu et al. Enforcing unique code target property for control-flow integrity. In Proc. ACM CCS ’15, pages 1470–1486, 2018. [[Hu_EnforcingUniqueCodeTargetProperty_2018]] [OA](https://api.scholarcy.com/oa_version?query=Hu%2C%20Hong%20Enforcing%20unique%20code%20target%20property%20for%20control-flow%20integrity%202018) [GScholar](https://scholar.google.co.uk/scholar?q=Hu%2C%20Hong%20Enforcing%20unique%20code%20target%20property%20for%20control-flow%20integrity%202018) [Scite](https://api.scholarcy.com/scite_url?query=Hu%2C%20Hong%20Enforcing%20unique%20code%20target%20property%20for%20control-flow%20integrity%202018)

[^29]: Intel Corporation. managed/4d/2a/control-flow-enforcementtechnology-preview.pdf, 2019. [[Intel__2019]] [OA](https://scholar.google.co.uk/scholar?q=Intel%20Corporation%20managed4d2acontrolflowenforcementtechnologypreviewpdf%202019) [GScholar](https://scholar.google.co.uk/scholar?q=Intel%20Corporation%20managed4d2acontrolflowenforcementtechnologypreviewpdf%202019) 

[^30]: Tim Kornau. Return Oriented Programming for the ARM Architecture. PhD thesis, Ruhr-Universität Bochum, 2009. [[Kornau_ReturnOrientedProgrammingArmArchitecture_2009]] [OA](https://scholar.google.co.uk/scholar?q=Kornau%2C%20Tim%20Return%20Oriented%20Programming%20for%20the%20ARM%20Architecture%202009) [GScholar](https://scholar.google.co.uk/scholar?q=Kornau%2C%20Tim%20Return%20Oriented%20Programming%20for%20the%20ARM%20Architecture%202009) 

[^31]: Volodymyr Kuznetsov et al. Code-pointer integrity. In Proc. USENIX OSDI ’14, pages 147–163, 2014. [[Kuznetsov_CodepointerIntegrity_2014]] [OA](https://api.scholarcy.com/oa_version?query=Kuznetsov%2C%20Volodymyr%20Code-pointer%20integrity%202014) [GScholar](https://scholar.google.co.uk/scholar?q=Kuznetsov%2C%20Volodymyr%20Code-pointer%20integrity%202014) [Scite](https://api.scholarcy.com/scite_url?query=Kuznetsov%2C%20Volodymyr%20Code-pointer%20integrity%202014)

[^32]: Per Larsen et al. SoK: Automated software diversity. In Proc. IEEE S&P ’14, pages 276–291, 2014. [[Larsen_SokAutomatedSoftwareDiversity_2014]] [OA](https://api.scholarcy.com/oa_version?query=Larsen%2C%20Per%20SoK%3A%20Automated%20software%20diversity%202014) [GScholar](https://scholar.google.co.uk/scholar?q=Larsen%2C%20Per%20SoK%3A%20Automated%20software%20diversity%202014) [Scite](https://api.scholarcy.com/scite_url?query=Larsen%2C%20Per%20SoK%3A%20Automated%20software%20diversity%202014)

[^33]: Gyungho Lee and Akhilesh Tyagi. Encoded program counter: Self-protection from buffer overflow attacks. In Proc. CSREA ICIC ’00, pages 387–394, 2000. [[Lee_EncodedProgramCounterSelfprotectionFrom_2000]] [OA](https://api.scholarcy.com/oa_version?query=Lee%2C%20Gyungho%20Tyagi%2C%20Akhilesh%20Encoded%20program%20counter%3A%20Self-protection%20from%20buffer%20overflow%20attacks%202000) [GScholar](https://scholar.google.co.uk/scholar?q=Lee%2C%20Gyungho%20Tyagi%2C%20Akhilesh%20Encoded%20program%20counter%3A%20Self-protection%20from%20buffer%20overflow%20attacks%202000) [Scite](https://api.scholarcy.com/scite_url?query=Lee%2C%20Gyungho%20Tyagi%2C%20Akhilesh%20Encoded%20program%20counter%3A%20Self-protection%20from%20buffer%20overflow%20attacks%202000)

[^34]: Jinfeng Li et al. Zipper stack: Shadow stacks without shadow. arXiv:1902.00888 [cs.CR], 2019. [[Li_ZipperStackShadowStacksWithout_2019]] [OA](https://arxiv.org/pdf/1902.00888)  

[^35]: Hans Liljestrand et al. PAC it up: Towards pointer integrity using ARM pointer authentication. In Proc. USENIX Security ’19, pages 177–194, 2019. [[Liljestrand_PacTowardsPointerIntegrity_2019]] [OA](https://api.scholarcy.com/oa_version?query=Liljestrand%2C%20Hans%20PAC%20it%20up%3A%20Towards%20pointer%20integrity%20using%20ARM%20pointer%20authentication%202019) [GScholar](https://scholar.google.co.uk/scholar?q=Liljestrand%2C%20Hans%20PAC%20it%20up%3A%20Towards%20pointer%20integrity%20using%20ARM%20pointer%20authentication%202019) [Scite](https://api.scholarcy.com/scite_url?query=Liljestrand%2C%20Hans%20PAC%20it%20up%3A%20Towards%20pointer%20integrity%20using%20ARM%20pointer%20authentication%202019)

[^36]: Lockheed Martin Corporation. Joint Strike Fighter Air Vehicle C++ Coding Standards (Revision C), 2005. [[Corporation_JointStrikeFighterAirVehicle_2005]] [OA](https://scholar.google.co.uk/scholar?q=Corporation%2C%20Lockheed%20Martin%20Joint%20Strike%20Fighter%20Air%20Vehicle%20C%2B%2B%20Coding%20Standards%202005) [GScholar](https://scholar.google.co.uk/scholar?q=Corporation%2C%20Lockheed%20Martin%20Joint%20Strike%20Fighter%20Air%20Vehicle%20C%2B%2B%20Coding%20Standards%202005) 

[^37]: Ali Jose Mashtizadeh et al. CCFI: Cryptographically enforced control flow integrity. In Proc. ACM CCS ’15, pages 941–951, 2015. [[Mashtizadeh_CcfiCryptographicallyEnforcedControlFlow_2015]] [OA](https://api.scholarcy.com/oa_version?query=Mashtizadeh%2C%20Ali%20Jose%20CCFI%3A%20Cryptographically%20enforced%20control%20flow%20integrity%202015) [GScholar](https://scholar.google.co.uk/scholar?q=Mashtizadeh%2C%20Ali%20Jose%20CCFI%3A%20Cryptographically%20enforced%20control%20flow%20integrity%202015) [Scite](https://api.scholarcy.com/scite_url?query=Mashtizadeh%2C%20Ali%20Jose%20CCFI%3A%20Cryptographically%20enforced%20control%20flow%20integrity%202015)

[^38]: Danny Nebenzahl, Mooly Sagiv, and Avishai Wool. Install-time vaccination of windows executables to defend against stack smashing attacks. IEEE Trans. Dependable Secur. Comput., 3(1):78–90, 2006. [[Nebenzahl_et+al_InstalltimeVaccinationWindowsExecutablesDefend_2006]] [OA](https://api.scholarcy.com/oa_version?query=Nebenzahl%2C%20Danny%20Sagiv%2C%20Mooly%20Wool%2C%20Avishai%20Install-time%20vaccination%20of%20windows%20executables%20to%20defend%20against%20stack%20smashing%20attacks%202006) [GScholar](https://scholar.google.co.uk/scholar?q=Nebenzahl%2C%20Danny%20Sagiv%2C%20Mooly%20Wool%2C%20Avishai%20Install-time%20vaccination%20of%20windows%20executables%20to%20defend%20against%20stack%20smashing%20attacks%202006) [Scite](https://api.scholarcy.com/scite_url?query=Nebenzahl%2C%20Danny%20Sagiv%2C%20Mooly%20Wool%2C%20Avishai%20Install-time%20vaccination%20of%20windows%20executables%20to%20defend%20against%20stack%20smashing%20attacks%202006)

[^39]: Thomas Nyman et al. CFI CaRE: Hardware-supported call and return enforcement for commercial microcontrollers. In Proc. RAID ’17, pages 259–284. Springer International Publishing, 2017. [[Nyman_CfiCareHardwaresupportedCallReturn_2017]] [OA](https://api.scholarcy.com/oa_version?query=Nyman%2C%20Thomas%20CFI%20CaRE%3A%20Hardware-supported%20call%20and%20return%20enforcement%20for%20commercial%20microcontrollers%202017) [GScholar](https://scholar.google.co.uk/scholar?q=Nyman%2C%20Thomas%20CFI%20CaRE%3A%20Hardware-supported%20call%20and%20return%20enforcement%20for%20commercial%20microcontrollers%202017) [Scite](https://api.scholarcy.com/scite_url?query=Nyman%2C%20Thomas%20CFI%20CaRE%3A%20Hardware-supported%20call%20and%20return%20enforcement%20for%20commercial%20microcontrollers%202017)

[^40]: H. Ozdoganoglu et al. SmashGuard: A hardware solution to prevent security attacks on the function return address. IEEE Trans. Comput., 55(10):1271–1285, 2006. [[Ozdoganoglu_SmashguardAHardwareSolutionPrevent_2006]] [OA](https://api.scholarcy.com/oa_version?query=Ozdoganoglu%2C%20H.%20SmashGuard%3A%20A%20hardware%20solution%20to%20prevent%20security%20attacks%20on%20the%20function%20return%20address%202006) [GScholar](https://scholar.google.co.uk/scholar?q=Ozdoganoglu%2C%20H.%20SmashGuard%3A%20A%20hardware%20solution%20to%20prevent%20security%20attacks%20on%20the%20function%20return%20address%202006) [Scite](https://api.scholarcy.com/scite_url?query=Ozdoganoglu%2C%20H.%20SmashGuard%3A%20A%20hardware%20solution%20to%20prevent%20security%20attacks%20on%20the%20function%20return%20address%202006)

[^41]: Seho Park, Yongsuk Lee, and Gyungho Lee. Program counter encoding for ARM® architecture. Journal of Information Security, 8:42–55, 2017. [[Park_et+al_ProgramCounterEncodingArmArchitecture_2017]] [OA](https://api.scholarcy.com/oa_version?query=Park%2C%20Seho%20Lee%2C%20Yongsuk%20Lee%2C%20Gyungho%20Program%20counter%20encoding%20for%20ARM%C2%AE%20architecture%202017) [GScholar](https://scholar.google.co.uk/scholar?q=Park%2C%20Seho%20Lee%2C%20Yongsuk%20Lee%2C%20Gyungho%20Program%20counter%20encoding%20for%20ARM%C2%AE%20architecture%202017) [Scite](https://api.scholarcy.com/scite_url?query=Park%2C%20Seho%20Lee%2C%20Yongsuk%20Lee%2C%20Gyungho%20Program%20counter%20encoding%20for%20ARM%C2%AE%20architecture%202017)

[^42]: Yong-Joon Park and Gyungho Lee. Repairing return address stack for buffer overflow protection. In Proc. ACM CF ’04, pages 335–342, 2004. [[Park_RepairingReturnAddressStackBuffer_2004]] [OA](https://api.scholarcy.com/oa_version?query=Park%2C%20Yong-Joon%20Lee%2C%20Gyungho%20Repairing%20return%20address%20stack%20for%20buffer%20overflow%20protection%202004) [GScholar](https://scholar.google.co.uk/scholar?q=Park%2C%20Yong-Joon%20Lee%2C%20Gyungho%20Repairing%20return%20address%20stack%20for%20buffer%20overflow%20protection%202004) [Scite](https://api.scholarcy.com/scite_url?query=Park%2C%20Yong-Joon%20Lee%2C%20Gyungho%20Repairing%20return%20address%20stack%20for%20buffer%20overflow%20protection%202004)

[^43]: Theofilos Petsios et al. DynaGuard: Armoring canarybased protections against brute-force attacks. In Proc. ACM ACSAC ’15, pages 351–360, 2015. [[Petsios_DynaguardArmoringCanarybasedProtectionsAgainst_2015]] [OA](https://api.scholarcy.com/oa_version?query=Petsios%2C%20Theofilos%20DynaGuard%3A%20Armoring%20canarybased%20protections%20against%20brute-force%20attacks%202015) [GScholar](https://scholar.google.co.uk/scholar?q=Petsios%2C%20Theofilos%20DynaGuard%3A%20Armoring%20canarybased%20protections%20against%20brute-force%20attacks%202015) [Scite](https://api.scholarcy.com/scite_url?query=Petsios%2C%20Theofilos%20DynaGuard%3A%20Armoring%20canarybased%20protections%20against%20brute-force%20attacks%202015)

[^44]: Changwoo Pyo and Gyungho Lee. Encoding function pointers and memory arrangement checking against buffer overflow attack. In Proc. ICICS ’02, pages 25–36, 2002. [[Pyo_EncodingFunctionPointersMemoryArrangement_2002]] [OA](https://api.scholarcy.com/oa_version?query=Pyo%2C%20Changwoo%20Lee%2C%20Gyungho%20Encoding%20function%20pointers%20and%20memory%20arrangement%20checking%20against%20buffer%20overflow%20attack%202002) [GScholar](https://scholar.google.co.uk/scholar?q=Pyo%2C%20Changwoo%20Lee%2C%20Gyungho%20Encoding%20function%20pointers%20and%20memory%20arrangement%20checking%20against%20buffer%20overflow%20attack%202002) [Scite](https://api.scholarcy.com/scite_url?query=Pyo%2C%20Changwoo%20Lee%2C%20Gyungho%20Encoding%20function%20pointers%20and%20memory%20arrangement%20checking%20against%20buffer%20overflow%20attack%202002)

[^45]: Qualcomm. Pointer authentication on ARMv8.3. https://www.qualcomm.com/media/documents/files/whitepaper-pointer-authentication-onarmv8-3.pdf, 2017. [[Qualcomm_PointerAuthenticationArmv83_2017]] [OA](https://www.qualcomm.com/media/documents/files/whitepaper-pointer-authentication-onarmv8-3.pdf)  

[^46]: Nick Roessler and Andre DeHon. Protecting the stack with metadata policies and tagged hardware. In Proc. IEEE S&P ’18, pages 478–495, 2018. [[Roessler_ProtectingStackWithMetadataPolicies_2018]] [OA](https://api.scholarcy.com/oa_version?query=Roessler%2C%20Nick%20DeHon%2C%20Andre%20Protecting%20the%20stack%20with%20metadata%20policies%20and%20tagged%20hardware%202018) [GScholar](https://scholar.google.co.uk/scholar?q=Roessler%2C%20Nick%20DeHon%2C%20Andre%20Protecting%20the%20stack%20with%20metadata%20policies%20and%20tagged%20hardware%202018) [Scite](https://api.scholarcy.com/scite_url?query=Roessler%2C%20Nick%20DeHon%2C%20Andre%20Protecting%20the%20stack%20with%20metadata%20policies%20and%20tagged%20hardware%202018)

[^47]: Nigel P. Smart. Cryptography Made Simple. Springer Publishing Company, 1st edition, 2015. [[Smart_CryptographyMadeSimple_2015]] [OA](https://scholar.google.co.uk/scholar?q=Smart%2C%20Nigel%20P.%20Cryptography%20Made%20Simple%202015) [GScholar](https://scholar.google.co.uk/scholar?q=Smart%2C%20Nigel%20P.%20Cryptography%20Made%20Simple%202015) 

[^48]: Solar Designer. lpr LIBC RETURN exploit. http://insecure.org/sploits/linux.libc.return.lpr.sploit.html, 1997. [[Designer_LibcReturnExploit_1997]] [OA](http://insecure.org/sploits/linux.libc.return.lpr.sploit.html)  

[^49]: László Szekeres et al. SoK: Eternal war in memory. In Proc. IEEE S&P ’13, pages 48–62, 2013. [[Szekeres_SokEternalMemory_2013]] [OA](https://api.scholarcy.com/oa_version?query=Szekeres%2C%20L%C3%A1szl%C3%B3%20SoK%3A%20Eternal%20war%20in%20memory%202013) [GScholar](https://scholar.google.co.uk/scholar?q=Szekeres%2C%20L%C3%A1szl%C3%B3%20SoK%3A%20Eternal%20war%20in%20memory%202013) [Scite](https://api.scholarcy.com/scite_url?query=Szekeres%2C%20L%C3%A1szl%C3%B3%20SoK%3A%20Eternal%20war%20in%20memory%202013)

[^50]: Caroline Tice et al. Enforcing forward-edge controlflow integrity in GCC & LLVM. In Proc. USENIX Security ’14, pages 941–955, 2014. [[Tice_EnforcingForwardedgeControlflowIntegrityGcc_2014]] [OA](https://api.scholarcy.com/oa_version?query=Tice%2C%20Caroline%20Enforcing%20forward-edge%20controlflow%20integrity%20in%20GCC%20%26%20LLVM%202014) [GScholar](https://scholar.google.co.uk/scholar?q=Tice%2C%20Caroline%20Enforcing%20forward-edge%20controlflow%20integrity%20in%20GCC%20%26%20LLVM%202014) [Scite](https://api.scholarcy.com/scite_url?query=Tice%2C%20Caroline%20Enforcing%20forward-edge%20controlflow%20integrity%20in%20GCC%20%26%20LLVM%202014)

[^51]: Victor van der Veen et al. Practical Context-Sensitive CFI. In Proc. ACM CCS ’15, pages 927–940, 2015. [[van_der_Veen_PracticalContextsensitiveCfi_2015]] [OA](https://api.scholarcy.com/oa_version?query=van%20der%20Veen%2C%20Victor%20Practical%20Context-Sensitive%20CFI%202015) [GScholar](https://scholar.google.co.uk/scholar?q=van%20der%20Veen%2C%20Victor%20Practical%20Context-Sensitive%20CFI%202015) [Scite](https://api.scholarcy.com/scite_url?query=van%20der%20Veen%2C%20Victor%20Practical%20Context-Sensitive%20CFI%202015)

[^52]: Xiaoyang Xu et al. CONFIRM: Evaluating compatibility and relevance of control-flow integrity protections for modern software. In Proc. USENIX Security ’19, pages 1805–1821, 2019.  [[Xu_ConfirmEvaluatingCompatibilityRelevanceControlflow_2019]] [OA](https://api.scholarcy.com/oa_version?query=Xu%2C%20Xiaoyang%20CONFIRM%3A%20Evaluating%20compatibility%20and%20relevance%20of%20control-flow%20integrity%20protections%20for%20modern%20software%202019) [GScholar](https://scholar.google.co.uk/scholar?q=Xu%2C%20Xiaoyang%20CONFIRM%3A%20Evaluating%20compatibility%20and%20relevance%20of%20control-flow%20integrity%20protections%20for%20modern%20software%202019) [Scite](https://api.scholarcy.com/scite_url?query=Xu%2C%20Xiaoyang%20CONFIRM%3A%20Evaluating%20compatibility%20and%20relevance%20of%20control-flow%20integrity%20protections%20for%20modern%20software%202019)

