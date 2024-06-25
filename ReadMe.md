# QueueUserApc-PoC

This Is A C# PoC Which Spawns Calculator By Abusing The QueueUserApc Special Flag.

As Found At [Online Information Source](https://repnz.github.io/posts/apc/user-apc/)
```
In RS5, Microsoft Implemented The Special User APC. The Special User APC Can Be Used To Force A Thread To Execute An APC Routine, Even If It’s Not In An Alertable State.
When RS5 Was Released, Microsoft Did Not Want To Add Another System Call (Yet) So They Changed NtQueueApcThreadEx To Support Special User APCs By Turning The MemoryReserveHandle Into A Union:
```

This PoC Has The Gets The Main Thread At Index 0 Allocates Memory Writes Our x64 Payload Then Queues The Memory As The Apc Routine With The Special Flag.
The Code Is Fully Commented To Help Show How This Method Works If You Like This Kindly Give Me A Star <3 ~ Immune

Example Usage Code
```cs
Process Target = Process.GetProcessesByName("Example")[0];
ApcInjection.Inject(Target.Threads[0].Id, Target.Handle);
```

As Of Right Now The Call For NtQueueApcThreadEx Throws An Error For Access Violation But It Still Spawns The Calculation So I Might Look Into That Later Hope Someone Can Learn From This And If You Have Any Good Changes Please Make A Pull Request Or Issues If You Have Issues Too.
