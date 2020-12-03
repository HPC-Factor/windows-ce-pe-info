export const WinCEArchitectures = ["X86", "SH3", "SH4", "ARM", "XSCALE", "MIPS"] as const;
export type WinCEArchitecture = typeof WinCEArchitectures[number];