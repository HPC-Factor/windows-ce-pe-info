import { WinCEArchitecture } from "./WindowsCEArchitecture";
import { WinCECoreVersion } from "./WindowsCECoreVersion";

export type WinCECabInfo = {
    /** Target architecture for this cabinet: see Appendix A */
    TargetArchitecture: WinCEArchitecture;
    /** Minimal version of WinCE (major version number) required to install this cabinet, or 0 to indicate no restriction */
    MinCEVersion: WinCECoreVersion;
    /** Minimal version of WinCE (major version number) required to install this cabinet, or 0 to indicate no restriction */
    MinCEVersionMajor: number;
    /** Minimal version of WinCE (minor version number) required to install this cabinet, or 0 to indicate no restriction */
    MinCEVersionMinor: number;
    /** Maximal version of WinCE (major version number) required to install this cabinet, or 0 to indicate no restriction */
    MaxCEVersion: WinCECoreVersion;
    /** Maximal version of WinCE (major version number) required to install this cabinet, or 0 to indicate no restriction */
    MaxCEVersionMajor: number;
    /** Maximal version of WinCE (minor version number) required to install this cabinet, or 0 to indicate no restriction */
    MaxCEVersionMinor: number;
    /** Minmal version of WinCE (build number) required to install this cabinet, or 0 to indicate no restriction */
    MinCEBuildNumber: number;
    /** Maximal version of WinCE (build number) required to install this cabinet, or 0 to indicate no restriction */
    MaxCEBuildNumber: number;
    /** APPNAME string */
    Appname: string;
    /** PROVIDER string */
    Provider: string;
    /** UNSUPPORTED multi string */
    Unsupported: string;
};