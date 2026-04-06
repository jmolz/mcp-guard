import koffi from 'koffi';
import { AuthError } from '../errors.js';

export interface PeerCredentials {
  uid: number;
  gid: number;
  pid?: number;
}

let getPeerCredentialsFn: ((socketFd: number) => PeerCredentials) | undefined;

function initMacOS() {
  const lib = koffi.load('libc.dylib');

  const getpeereid = lib.func('int getpeereid(int, _Out_ uint32_t *, _Out_ uint32_t *)');
  const getsockopt = lib.func(
    'int getsockopt(int, int, int, _Out_ uint8_t *, _Inout_ uint32_t *)',
  );

  return (socketFd: number): PeerCredentials => {
    const uidBuf = [0];
    const gidBuf = [0];

    const rc = getpeereid(socketFd, uidBuf, gidBuf);
    if (rc !== 0) {
      throw new AuthError(`getpeereid failed with rc=${rc}`);
    }

    // LOCAL_PEERPID: level=0 (SOL_LOCAL), optname=2
    const pidBuf = Buffer.alloc(4);
    const lenBuf = [4];
    const pidRc = getsockopt(socketFd, 0, 2, pidBuf, lenBuf);
    const pid = pidRc === 0 ? pidBuf.readUInt32LE(0) : undefined;

    return { uid: uidBuf[0], gid: gidBuf[0], pid };
  };
}

function initLinux() {
  const lib = koffi.load('libc.so.6');

  // struct ucred { pid_t pid; uid_t uid; gid_t gid; }
  // Registration is required for koffi to recognize the type in the function signature
  koffi.struct('ucred', {
    pid: 'int',
    uid: 'uint32_t',
    gid: 'uint32_t',
  });

  const getsockopt = lib.func('int getsockopt(int, int, int, _Out_ ucred *, _Inout_ uint32_t *)');

  // SOL_SOCKET=1, SO_PEERCRED=17
  return (socketFd: number): PeerCredentials => {
    const cred = { pid: 0, uid: 0, gid: 0 };
    const lenBuf = [12]; // sizeof(ucred)

    const rc = getsockopt(socketFd, 1, 17, cred, lenBuf);
    if (rc !== 0) {
      throw new AuthError(`getsockopt SO_PEERCRED failed with rc=${rc}`);
    }

    return { uid: cred.uid, gid: cred.gid, pid: cred.pid };
  };
}

export function getPeerCredentials(socketFd: number): PeerCredentials {
  if (!getPeerCredentialsFn) {
    if (process.platform === 'darwin') {
      getPeerCredentialsFn = initMacOS();
    } else if (process.platform === 'linux') {
      getPeerCredentialsFn = initLinux();
    } else {
      throw new AuthError(`Unsupported platform for peer credentials: ${process.platform}`);
    }
  }
  return getPeerCredentialsFn(socketFd);
}

export function verifyPeerIsCurrentUser(creds: PeerCredentials): boolean {
  if (!process.getuid) {
    throw new AuthError('process.getuid not available on this platform');
  }
  return creds.uid === process.getuid();
}
