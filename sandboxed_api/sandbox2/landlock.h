// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef SECURITY_SANDBOXED_API_SANDBOX2_LANDLOCK_H_
#define SECURITY_SANDBOXED_API_SANDBOX2_LANDLOCK_H_

#include "sandboxed_api/sandbox2/mounts.h"

namespace sandbox2 {

// Declares the caller's explicit security posture when using Landlock.
enum class LandlockSecurityPosture {
  // Strict mode (Default): Requires Landlock ABI v6+ (Linux 6.12+).
  // Hermetically isolates filesystem, signals, and abstract UNIX sockets.
  // Fails if runtime kernel Landlock ABI version is < 6.
  kStrictV6 = 0,

  // Compensated mode (Linux 5.13+ / ABI v1-v5):
  // Enables Landlock filesystem restrictions on earlier kernels where
  // signal scoping (ABI v6) and abstract UNIX socket scoping (ABI v6)
  // are not natively supported by kernel Landlock. Callers rely on
  // Sandbox2 seccomp-bpf filters to isolate signals and sockets.
  kCompensatedOlderKernels,

  // Explicit unconfined-signals mode:
  // Caller explicitly acknowledges that on kernels < 6.12, signal and
  // abstract socket restrictions are NOT enforced by Landlock.
  kExplicitFilesystemOnly,
};

// Returns the Landlock ABI version supported by the running kernel,
// or -1 if Landlock is unsupported or disabled.
int GetLandlockAbiVersion();

// Enforces Landlock access rules based on the requested Sandbox2 mounts.
//
// Note: Landlock support is experimental and subject to change.
// Certain file-related syscall families (e.g., access(2), stat(2), chdir(2),
// flock(2), chmod(2), chown(2), setxattr(2), utime(2), fcntl(2)) are not
// currently restricted by kernel Landlock access controls. These unhandled
// syscalls primarily allow metadata probing (e.g., file existence) or CWD
// navigation and cannot be used to read, write, or execute unauthorized file
// contents, and thus do not materially expand the sandbox attack surface.
// Future Landlock ABI versions will support restricting these syscalls, and
// Sandbox2 will be updated as new kernel features become available.
void EnforceLandlock(
    const Mounts& mounts,
    LandlockSecurityPosture posture = LandlockSecurityPosture::kStrictV6);

// Returns whether Landlock is supported on the current kernel for the given
// posture.
bool IsLandlockSupported(
    LandlockSecurityPosture posture = LandlockSecurityPosture::kStrictV6);

}  // namespace sandbox2

#endif  // SECURITY_SANDBOXED_API_SANDBOX2_LANDLOCK_H_
