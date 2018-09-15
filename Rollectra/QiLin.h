//
//  jjt.h
//  QiLin
//
//  Created by JL on 12/7/17.
//  Copyright © 2017 NewOSXBook. All rights reserved.

// Revision 3: Added spawnAndPlatformize(),
//             moved to posix_spawn() implementation for exec() family
//             actually exported the set*Reporter functions (formerly ErrorHandler.. etc -
//             "Reporter" is more accurate, because they allow you to propagate messages to
//             a GUI.
//
// Revision 4: Added kexec (executeInKernel)
//
// Revision 5: KMR/KMW (Kernel memory read/write) functions weren't exported! Oops!
//
// Revision 6: RootFS mount, fixed bug in getting symbols (no longer needs setKernelSymbol)
//             and added respring
//             and also added uint64_t        getVnodeByPathName (char *Path) ;
//
// (Almost) free to use (ABSE) per the license in http://NewOSXBook.com/QiLin/
//        
//          Remember to give credit where due and please tweet with #QiLin
//          so others can quickly find your JailBreak or other project.
//

#if 0
Johnny's (semi) open source license, v0.4
-----------------------------------------

This is (well, will be, at the time of writing) open source, and I can't but appeal to your sense of decency. 
You might try compile this and try to pass it as your own. Heck, you might even try to run it through llvm-obfuscator. 
But that would be stealing code. And obfuscate as you will, you can't obfuscate enough to hide the methods. 
So, primum non nocere. Do no harm, and do not steal.

To be fully clear:

 - Yes, you may use this source or code library as you see fit, PROVIDED THAT:

	- IT IS NOT USED COMMERCIALLY IN ANY WAY. For this, I ask that you contact my company, @Technologeeks, 
		and ask for proper licensing - they'll also provide official support.

	- IT IS NOT USED AS A COMPONENT OF AN APT IN ANY KIND FORM OR MANNER. 
		(NSO/Hackin9/Finfisher/Equus/etc - that means you)

	- WHEN YOU DO USE IT, I ASK THAT YOU MENTION THAT YOUR TOOL IS "powered by the QiLin Toolkit", 
          or otherwise provide a user facing indication that it is using this code. 
	   I'd appreciate it if you tweeted with #QiLin, too.

	- If you spread lies about other people, propaganda or false claims, while using this toolkit, 
then you must renounce your ways, and apologize. Then you can use it freely.

  - There are no limitation on nationality, specific people exclusions (i.e. this is AISE, subject to last condition, above ;-), 
or any other race, color or creed - provided the above are met.


  - QiLin comes with NO LIABILITY WHATSOEVER. YOU USE THIS AT YOUR OWN RISK. 

    I CANNOT AND WILL NOT BE HELD ACCOUNTABLE FOR ANY DAMAGE, SOFTWARE OR HARDWARE OR YOUR DATA OR OTHERWISE, 

    WHICH MAY OR MAY NOT RESULT TO YOUR IOS DEVICE BY USING THIS. 
 
  - Remember I'm doing this AS A FAVOR. I AM NO IN WAY INDEBTED OR COMMITTED TO SUPPORT THIS, OR ANY OTHER OF MY TOOLS.
    You don't have to thank for this (you're welcome) but please don't slander me either.

  - Should you wish to contribute/donate, you may do so in one of the following ways:

	- Monetary: Pick a charity. Any charity. Of your choice. Pay them however money you want. 
		    Optionally, tweet/fb/insta/snap-whatever a screen capture stating "#QiLin". 

        - Development: Through http://NewOSXBook.com/forum - you are welcome to ask (proper technical, not lame wen eta) 
			questions and engage in discussions
	


First, do no harm. Next, have fun :-)

Changelog:

- v0.1 Was AISE but SE is being more of an ass than usual and slandering fake claims directly attacking me. 
So this was updated with new condition excluding him until he grows up and behaves like the decent, 
talented researcher he can be.

- v0.3 adds request to tweet #QiLin. 

- v0.4 states what should be obvious - NO LIABILITY WHATSOEVER
#endif
#ifndef qilin_h 
#define qilin_h
#include <mach/mach.h>
#include <unistd.h>
#include <stdlib.h>


char *getMachine (void);
char *getOSVer(void);

typedef int  (*KMRFunc)(uint64_t Address, uint64_t Len, void **To);
typedef int  (*KMWFunc)(uint64_t Address, uint64_t Len, void *From);
void setKernelMemoryReadFunction(KMRFunc F);
void setKernelMemoryWriteFunction(KMWFunc F);


// MUST call either initQiLin variant first - with or without TFP0, though, that's your call.

int initQiLin (mach_port_t TFP0, uint64_t KernelBase);
int initQiLinWithKMRW(uint64_t KernelBase, KMRFunc Kmr, KMWFunc Kmw);
int initQilinWithTFP0AndMyTaskPortAddr(mach_port_t TFP0, uint64_t MyTaskPortAddr);


// System wide effects
//
int remountRootFS (void);
int reSpring (void);        // @FCE365 - this is for you

pid_t execCommand(char *Cmd, char *Arg1, char *Arg2, char *Arg3, char *Arg4, char *Arg5 , int Flags);
int execCommandAndWait(char *Cmd, char *Arg1, char *Arg2, char *Arg3, char *Arg4, char *Arg5);

int setTFP0AsHostSpecialPort4 (void);

// 1/17/18 - This is super useful
int spawnAndPlatformize (char *AmfidebPath, char *Arg1, char *Arg2, char *Arg3 , char *Arg4, char *Arg5);
int spawnAndShaiHulud (char *AmfidebPath, char *Arg1, char *Arg2, char *Arg3 , char *Arg4, char *Arg5);


int moveFileFromAppDir (char *File, char *Dest);
int disableAutoUpdates(void);

// Code signing

// Will set AMFId's exception ports and thereby disable code signing
//
int castrateAmfid (void);

// Utility function - you probably won't need this directly.
#define ALGORITHM_SHA256    2
#define ALGORITHM_SHA1      1
char *cdHashOfFile(char *fileName,int Algorithm); // Calculate CDHash of a given Mach-O (for messing with AMFI)



// Kernel Memory access (wrappers over kernel_task send right)
uint64_t findKernelSymbol (char *Symbol);
void setKernelSymbol (char *Symbol, uint64_t Address); // NOTE: "_kernproc", not "kernproc"

int readKernelMemory(uint64_t Address, uint64_t Len, void **To);
int writeKernelMemory(uint64_t Address, uint64_t Len, void *From);

// 03/20/2018: Kernel execution

int kexec(uint64_t Address, uint64_t Arg0, uint64_t Arg1,uint64_t Arg2,uint64_t Arg3,uint64_t Arg4,uint64_t Arg5,uint64_t Arg6);


// 03/20/2018
uint64_t getAddressOfPort(pid_t Pid, mach_port_name_t Port);

// 06/15/2018 -------
// Will return the address of the kernel vnode representing Path.
uint64_t        getVnodeByPathName (char *Path) ;
uint64_t getRootVnodeAddr(void); // Convenience, for rootvnode ("/") instead of _rootvnode sym deref

//-------------------

// Not recommended, but doable: Bestow task port of Pid in TargetPid
mach_port_t task_for_pid_in_kernel (pid_t Pid, pid_t TargetPid);

//--------------------------------------

// Process manipulation functions

// Finds the address of struct proc for this pid_t in kernel memory.
uint64_t getProcStructForPid(pid_t);

// Finds the pid of a process given its (base) name. Note this will only
// work on processes you are the owner of (or all, if root) - this is intentional
pid_t findPidOfProcess (char *ProcName) ;

int setCSFlagsForProcAtAddr(uint64_t ProcStructAddr, int Flags, int Set);
int setCSFlagsForPid (pid_t Whom, uint32_t Flags);
int platformizePid(pid_t Whom);
int rootifyPid(pid_t Whom);
int ShaiHuludPid (pid_t Whom, uint64_t CredAddr); // leave 0 for root creds.
int unShaiHuludPid (pid_t Whom);

int platformizeProcAtAddr(uint64_t thing);
uint64_t borrowEntitlementsFromDonor(char *UnwittingDonor, char *Arg);
// By request :-)
uint64_t borrowEntitlementsFromPid(pid_t    Pid);



// Presently, limited to two entitlements, and assumed boolean (true)
int entitlePidWithKernelEnts (pid_t Whom, char *Ent1, char *Ent2);

// Convenience functions - do all the above , but on my process

int platformizeMe (void);
int rootifyMe(void);

// Escape sandbox:
// call with 0 to assume kernel cred, else specify value. Will return origCreds
uint64_t ShaiHuludMe(uint64_t OtherCredsOr0ForKernelCreds);
void unShaiHuludMe(uint64_t OrigCreds);
int entitleMe(char *entitlementString);

uint64_t getKernelCredAddr (void);


/// Vnode functions - bringing @MinZheng's APFS bypass to the masses:
uint64_t        getVnodeByPathName (char *Path);

/// Launchd handling utilities - just for you @launchderp :-)
int makeLaunchdPlist (char *PlistName, char *Program, char *ProgramArguments, char *StandardOutputPath, char *StandardErrorPath, int RunAtLoad);
int launjctlLaunchdPlist(char *Name);

// I use these internally, not sure anyone else would need them
int launjctlPrintSystem (void);
int launjctlDumpState(void);


// This one is still in progress. Don't use it please.
int movePortToPid(mach_port_t PortMoved, pid_t Pid, mach_port_name_t Name);
int spawnJailbreakServer (char *Name, mach_port_t TFP0, mach_port_name_t NameInTarget);

// UI Support:
// Provide status, error and debug print outs to user,
// which may be redirected to GUI views, etc.
// Default implmenentations are NSLog.

typedef void (status_func) (char *,...);
void setStatusReporter (status_func *Func);
void setErrorReporter (status_func *Func);
void setDebugReporter (status_func *Func);


// Utility functions you probably won't need unless you want to do your own debugging
void hexDump(void *Mem, int Len, uint64_t Addr);
void dumpARMThreadState64(_STRUCT_ARM_THREAD_STATE64 *old_state);

// Even more Internal/advanced use:
uint64_t findKernelTask (void);
uint64_t findMyProcStructInKernelMemory(void);  // For other advanced uses I haven't provided already


#endif /* qilin_h */
