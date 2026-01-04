/**************************************************************************************************
 * 🛡️ SOCUTE.APK - Unified Android Interception Engine
 * ------------------------------------------------------------------------------------------------
 * Build Date : January 04, 2026
 * Author     : Milio48 (socute.apk)
 * Source     : https://github.com/httptoolkit/frida-interception-and-unpinning
 * License    : AGPL-3.0-or-later
 *
 * [MERGE SEQUENCE]
 * 1. config, 2. native-connect, 3. native-tls, 4. proxy-override,
 * 5. cert-injection, 6. unpinning, 7. fallback, 8. flutter, 9. anti-root
 **************************************************************************************************/

/** [MODULE 1] Core Configuration & Utilities */
/**************************************************************************************************
 *
 * This file defines various config parameters, used later within the other scripts.
 *
 * In all cases, you'll want to set CERT_PEM and likely PROXY_HOST and PROXY_PORT.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 *
 *************************************************************************************************/

// Put your CA certificate data here in PEM format:
const CERT_PEM = `{{SOCUTE_CERT_PEM}}`;

// Put your intercepting proxy's address here:
const PROXY_HOST = '{{SOCUTE_PROXY_HOST}}';
const PROXY_PORT = {{SOCUTE_PROXY_PORT}};

// If you like, set to to true to enable extra logging:
const DEBUG_MODE = {{SOCUTE_DEBUG_MODE}};

// If you find issues with non-HTTP traffic being captured (due to the
// native connect hook script) you can add ports here to exempt traffic
// on that port from being redirected. Note that this will only affect
// traffic captured by the raw connection hook - for apps using the
// system HTTP proxy settings, traffic on these ports will still be
// sent via the proxy and intercepted despite this setting.
const IGNORED_NON_HTTP_PORTS = {{SOCUTE_IGNORED_PORTS}};

// As HTTP/3 is often not well supported by MitM proxies, by default it
// is blocked entirely, so all outgoing UDP connections to port 443
// will fail. If this is set to false, they will instead be left unintercepted.
const BLOCK_HTTP3 = {{SOCUTE_BLOCK_HTTP3}};

// Set this to true if your proxy supports SOCKS5 connections.
// This makes it possible for native-connect-hook to redirect
// non-HTTP traffic through your proxy (to view it raw, and
// avoid breaking non-HTTP traffic en route).
const PROXY_SUPPORTS_SOCKS5 = {{SOCUTE_SOCKS5_SUPPORT}};


// ----------------------------------------------------------------------------
// You don't need to modify any of the below, it just checks and applies some
// of the configuration that you've entered above.
// ----------------------------------------------------------------------------


if (DEBUG_MODE) {
    // Add logging just for clean output & to separate reloads:
    console.log('\n*** Starting scripts ***');
    if (globalThis.Java?.available) {
        Java.perform(() => {
            setTimeout(() => console.log('*** Scripts completed ***\n'), 5);
            // (We assume that nothing else will take more than 5ms, but app startup
            // probably will, so this should separate script & runtime logs)
        });
    } else {
        setTimeout(() => console.log('*** Scripts completed ***\n'), 5);
        // (We assume that nothing else will take more than 5ms, but app startup
        // probably will, so this should separate script & runtime logs)
    }
} else {
    console.log(''); // Add just a single newline, for minimal clarity
}

// Check the certificate (without literally including the instruction phrasing
// here, as that can be confusing for some users):
if (CERT_PEM.match(/\[!!.* CA certificate data .* !!\]/)) {
    throw new Error('No certificate was provided' +
        '\n\n' +
        'You need to set CERT_PEM in the Frida config script ' +
        'to the contents of your CA certificate.'
    );
}



// ----------------------------------------------------------------------------
// Don't modify any of the below unless you know what you're doing!
// This section defines various utilities & calculates some constants which may
// be used by later scripts elsewhere in this project.
// ----------------------------------------------------------------------------



// As web atob & Node.js Buffer aren't available, we need to reimplement base64 decoding
// in pure JS. This is a quick rough implementation without much error handling etc!

// Base64 character set (plus padding character =) and lookup:
const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
const BASE64_LOOKUP = new Uint8Array(123);
for (let i = 0; i < BASE64_CHARS.length; i++) {
    BASE64_LOOKUP[BASE64_CHARS.charCodeAt(i)] = i;
}


/**
 * Take a base64 string, and return the raw bytes
 * @param {string} input
 * @returns Uint8Array
 */
function decodeBase64(input) {
    // Calculate the length of the output buffer based on padding:
    let outputLength = Math.floor((input.length * 3) / 4);
    if (input[input.length - 1] === '=') outputLength--;
    if (input[input.length - 2] === '=') outputLength--;

    const output = new Uint8Array(outputLength);
    let outputPos = 0;

    // Process each 4-character block:
    for (let i = 0; i < input.length; i += 4) {
        const a = BASE64_LOOKUP[input.charCodeAt(i)];
        const b = BASE64_LOOKUP[input.charCodeAt(i + 1)];
        const c = BASE64_LOOKUP[input.charCodeAt(i + 2)];
        const d = BASE64_LOOKUP[input.charCodeAt(i + 3)];

        // Assemble into 3 bytes:
        const chunk = (a << 18) | (b << 12) | (c << 6) | d;

        // Add each byte to the output buffer, unless it's padding:
        output[outputPos++] = (chunk >> 16) & 0xff;
        if (input.charCodeAt(i + 2) !== 61) output[outputPos++] = (chunk >> 8) & 0xff;
        if (input.charCodeAt(i + 3) !== 61) output[outputPos++] = chunk & 0xff;
    }

    return output;
}

/**
 * Take a single-certificate PEM string, and return the raw DER bytes
 * @param {string} input
 * @returns Uint8Array
 */
function pemToDer(input) {
    const pemLines = input.split('\n');
    if (
        pemLines[0] !== '-----BEGIN CERTIFICATE-----' ||
        pemLines[pemLines.length- 1] !== '-----END CERTIFICATE-----'
    ) {
        throw new Error(
            'Your certificate should be in PEM format, starting & ending ' +
            'with a BEGIN CERTIFICATE & END CERTIFICATE header/footer'
        );
    }

    const base64Data = pemLines.slice(1, -1).map(l => l.trim()).join('');
    if ([...base64Data].some(c => !BASE64_CHARS.includes(c))) {
        throw new Error(
            'Your certificate should be in PEM format, containing only ' +
            'base64 data between a BEGIN & END CERTIFICATE header/footer'
        );
    }

    return decodeBase64(base64Data);
}

const CERT_DER = pemToDer(CERT_PEM);

// Right now this API is a bit funky - the callback will be called with a Frida Module instance
// if the module is properly detected, but may be called with just { name, path, base, size }
// in some cases (e.g. shared libraries loaded from inside an APK on Android). Works OK right now,
// as it's not widely used but needs improvement in future if we extend this.
function waitForModule(moduleName, callback) {
    if (Array.isArray(moduleName)) {
        moduleName.forEach(module => waitForModule(module, callback));
    }

    try {
        const module = Process.getModuleByName(moduleName)
        module.ensureInitialized();
        callback(module);
        return;
    } catch (e) {
        try {
            const module = Module.load(moduleName);
            callback(module);
            return;
        } catch (e) {}
    }

    MODULE_LOAD_CALLBACKS[moduleName] = callback;
}

const getModuleName = (nameOrPath) => {
    const endOfPath = nameOrPath.lastIndexOf('/');
    return nameOrPath.slice(endOfPath + 1);
};

const MODULE_LOAD_CALLBACKS = {};
new ApiResolver('module').enumerateMatches('exports:linker*!*dlopen*').forEach((dlopen) => {
    Interceptor.attach(dlopen.address, {
        onEnter(args) {
            const moduleArg = args[0].readCString();
            if (moduleArg) {
                this.path = moduleArg;
                this.moduleName = getModuleName(moduleArg);
            }
        },
        onLeave(retval) {
            if (!this.path || !retval || retval.isNull()) return;
            if (!MODULE_LOAD_CALLBACKS[this.moduleName]) return;

            let module = Process.findModuleByName(this.moduleName)
                ?? Process.findModuleByAddress(retval);
            if (!module) {
                // Some modules are loaded in ways that mean Frida can't detect them, and
                // can't look them up by name (notably when loading libraries from inside an
                // APK on Android). To handle this, we can use dlsym to look up an example
                // symbol and find the underlying module details directly, where possible.
                module = getAnonymousModule(this.moduleName, this.path, retval);
                if (!module) return;
            }

            Object.keys(MODULE_LOAD_CALLBACKS).forEach((key) => {
                if (this.moduleName === key) {
                    if (module) {
                        MODULE_LOAD_CALLBACKS[key](module);
                        delete MODULE_LOAD_CALLBACKS[key];
                    }
                }
            });
        }
    });
});

const getAnonymousModule = (name, path, handle) => {
    const dlsymAddr = Module.findGlobalExportByName('dlsym');
    if (!dlsymAddr) {
        console.error(`[!] Cannot find dlsym, cannot get anonymous module info for ${name}`);
        return;
    }

    const dlsym = new NativeFunction(dlsymAddr, 'pointer', ['pointer', 'pointer']);

    // Handle here is the return value from dlopen - but in this scenario, it's just an
    // opaque handle into to 'soinfo' data that other methods can use to get the
    // real pointer to parts of the module, like so:
    const onLoadPointer = dlsym(handle, Memory.allocUtf8String('JNI_OnLoad'));

    // Once we have an actual pointer, we can get the range that holds it:
    const range = Process.getRangeByAddress(onLoadPointer);

    return {
        base: range.base,
        size: range.size,
        name,
        path,
    }
};
/** [MODULE 2] Low-Level Socket Redirection */
/**
 * In some cases, proxy configuration by itself won't work. This notably includes Flutter apps (which ignore
 * system/JVM configuration entirely) and plausibly other apps intentionally ignoring proxies. To handle that
 * we hook native connect() calls directly, to redirect traffic on all ports to the target.
 *
 * This handles all attempts to connect an outgoing socket, and for all TCP connections opened it will
 * manually replace the connect() parameters so that the socket connects to the proxy instead of the
 * 'real' destination.
 *
 * This doesn't help with certificate trust (you still need some kind of certificate setup) but it does ensure
 * the proxy receives all connections (and so will see if connections don't trust its CA). It's still useful
 * to do proxy config alongside this, as applications may behave a little more 'correctly' if they're aware
 * they're using a proxy rather than doing so unknowingly.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 */

(() => {
    const PROXY_HOST_IPv4_BYTES = PROXY_HOST.split('.').map(part => parseInt(part, 10));
    const IPv6_MAPPING_PREFIX_BYTES = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff];
    const PROXY_HOST_IPv6_BYTES = IPv6_MAPPING_PREFIX_BYTES.concat(PROXY_HOST_IPv4_BYTES);

    // Flags for fcntl():
    const F_GETFL = 3;
    const F_SETFL = 4;
    const O_NONBLOCK = (Process.platform === 'darwin')
        ? 4
        : 2048; // Linux/Android

    let fcntl, send, recv, conn;
    try {
        const systemModule = Process.findModuleByName('libc.so') ?? // Android
                             Process.findModuleByName('libc.so.6') ?? // Linux
                             Process.findModuleByName('libsystem_c.dylib'); // iOS

        if (!systemModule) throw new Error("Could not find libc or libsystem_c");

        fcntl = new NativeFunction(systemModule.getExportByName('fcntl'), 'int', ['int', 'int', 'int']);
        send = new NativeFunction(systemModule.getExportByName('send'), 'ssize_t', ['int', 'pointer', 'size_t', 'int']);
        recv = new NativeFunction(systemModule.getExportByName('recv'), 'ssize_t', ['int', 'pointer', 'size_t', 'int']);

        conn = systemModule.getExportByName('connect')
    } catch (e) {
        console.error("Failed to set up native hooks:", e.message);
        console.warn('Could not initialize system functions to to hook raw traffic');
        return;
    }

    Interceptor.attach(conn, {
        onEnter(args) {
            const fd = this.sockFd = args[0].toInt32();
            const sockType = Socket.type(fd);

            const addrPtr = ptr(args[1]);
            const addrLen = args[2].toInt32();
            const addrData = addrPtr.readByteArray(addrLen);

            const isTCP = sockType === 'tcp' || sockType === 'tcp6';
            const isUDP = sockType === 'udp' || sockType === 'udp6';
            const isIPv6 = sockType === 'tcp6' || sockType === 'udp6';

            if (isTCP || isUDP) {
                const portAddrBytes = new DataView(addrData.slice(2, 4));
                const port = portAddrBytes.getUint16(0, false); // Big endian!

                const shouldBeIgnored = IGNORED_NON_HTTP_PORTS.includes(port);
                const shouldBeBlocked = BLOCK_HTTP3 && !shouldBeIgnored && isUDP && port === 443;

                // N.b for now we only support TCP interception - UDP direct should be doable,
                // but SOCKS5 UDP would require a whole different flow. Rarely relevant, especially
                // if you're blocking HTTP/3.
                const shouldBeIntercepted = isTCP && !shouldBeIgnored && !shouldBeBlocked;

                const hostBytes = isIPv6
                    // 16 bytes offset by 8 (2 for family, 2 for port, 4 for flowinfo):
                    ? new Uint8Array(addrData.slice(8, 8 + 16))
                    // 4 bytes, offset by 4 (2 for family, 2 for port)
                    : new Uint8Array(addrData.slice(4, 4 + 4));

                const isIntercepted = port === PROXY_PORT && areArraysEqual(hostBytes,
                    isIPv6
                        ? PROXY_HOST_IPv6_BYTES
                        : PROXY_HOST_IPv4_BYTES
                );

                if (isIntercepted) return;

                if (shouldBeBlocked) {
                    if (isIPv6) {
                        // Skip 8 bytes: 2 family, 2 port, 4 flowinfo, then write :: (all 0s)
                        for (let i = 0; i < 16; i++) {
                            addrPtr.add(8 + i).writeU8(0);
                        }
                    } else {
                        // Skip 4 bytes: 2 family, 2 port, then write 0.0.0.0
                        addrPtr.add(4).writeU32(0);
                    }

                    console.debug(`Blocking QUIC connection to ${getReadableAddress(hostBytes, isIPv6)}:${port}`);
                    this.state = 'Blocked';
                } else if (shouldBeIntercepted) {
                    // Otherwise, it's an unintercepted connection that should be captured:
                    this.state = 'intercepting';

                    // For SOCKS, we preserve the original destionation to use in the SOCKS handshake later
                    // and we temporarily set the socket to blocking mode to do the handshake itself.
                    if (PROXY_SUPPORTS_SOCKS5) {
                        this.originalDestination = { host: hostBytes, port, isIPv6 };
                        this.originalFlags = fcntl(this.sockFd, F_GETFL, 0);
                        this.isNonBlocking = (this.originalFlags & O_NONBLOCK) !== 0;
                        if (this.isNonBlocking) {
                            fcntl(this.sockFd, F_SETFL, this.originalFlags & ~O_NONBLOCK);
                        }
                    }

                    console.log(`Manually intercepting ${sockType} connection to ${getReadableAddress(hostBytes, isIPv6)}:${port}`);

                    // Overwrite the port with the proxy port:
                    portAddrBytes.setUint16(0, PROXY_PORT, false); // Big endian
                    addrPtr.add(2).writeByteArray(portAddrBytes.buffer);

                    // Overwrite the address with the proxy address:
                    if (isIPv6) {
                        // Skip 8 bytes: 2 family, 2 port, 4 flowinfo
                        addrPtr.add(8).writeByteArray(PROXY_HOST_IPv6_BYTES);
                    } else {
                        // Skip 4 bytes: 2 family, 2 port
                        addrPtr.add(4).writeByteArray(PROXY_HOST_IPv4_BYTES);
                    }
                } else {
                    // Explicitly being left alone
                    if (DEBUG_MODE) {
                        console.debug(`Allowing unintercepted ${sockType} connection to port ${port}`);
                    }
                    this.state = 'ignored';
                }
            } else {
                // Should just be unix domain sockets - UDP & TCP are covered above
                if (DEBUG_MODE) console.log(`Ignoring ${sockType} connection`);
                this.state = 'ignored';
            }
        },
        onLeave: function (retval) {
            if (this.state === 'ignored') return;

            if (this.state === 'intercepting' && PROXY_SUPPORTS_SOCKS5) {
                const connectSuccess = retval.toInt32() === 0;

                let handshakeSuccess = false;

                const { host, port, isIPv6 } = this.originalDestination;
                if (connectSuccess) {
                    handshakeSuccess = performSocksHandshake(this.sockFd, host, port, isIPv6);
                } else {
                    console.error(`SOCKS: Failed to connect to proxy at ${PROXY_HOST}:${PROXY_PORT}`);
                }

                if (this.isNonBlocking) {
                    fcntl(this.sockFd, F_SETFL, this.originalFlags);
                }

                if (handshakeSuccess) {
                    const readableHost = getReadableAddress(host, isIPv6);
                    if (DEBUG_MODE) console.debug(`SOCKS redirect successful for fd ${this.sockFd} to ${readableHost}:${port}`);
                    retval.replace(0);
                } else {
                    if (DEBUG_MODE) console.error(`SOCKS redirect FAILED for fd ${this.sockFd}`);
                    retval.replace(-1);
                }
            } else if (DEBUG_MODE) {
                const fd = this.sockFd;
                const sockType = Socket.type(fd);
                const address = Socket.peerAddress(fd);
                console.debug(
                    `${this.state} ${sockType} fd ${fd} to ${JSON.stringify(address)} (${retval.toInt32()})`
                );
            }
        }
    });

    console.log(`== Redirecting ${
        IGNORED_NON_HTTP_PORTS.length === 0
        ? 'all'
        : 'all unrecognized'
    } TCP connections to ${PROXY_HOST}:${PROXY_PORT} ==`);

    const getReadableAddress = (
        /** @type {Uint8Array} */ hostBytes,
        /** @type {boolean} */ isIPv6
    ) => {
        if (!isIPv6) {
            // Return simple a.b.c.d IPv4 format:
            return [...hostBytes].map(x => x.toString()).join('.');
        }

        if (
            hostBytes.slice(0, 10).every(b => b === 0) &&
            hostBytes.slice(10, 12).every(b => b === 255)
        ) {
            // IPv4-mapped IPv6 address - print as IPv4 for readability
            return '::ffff:'+[...hostBytes.slice(12)].map(x => x.toString()).join('.');
        }

        else {
            // Real IPv6:
            return `[${[...hostBytes].map(x => x.toString(16)).join(':')}]`;
        }
    };

    const areArraysEqual = (arrayA, arrayB) => {
        if (arrayA.length !== arrayB.length) return false;
        return arrayA.every((x, i) => arrayB[i] === x);
    };

    function performSocksHandshake(sockfd, targetHostBytes, targetPort, isIPv6) {
        const hello = Memory.alloc(3).writeByteArray([0x05, 0x01, 0x00]);
        if (send(sockfd, hello, 3, 0) < 0) {
            console.error("SOCKS: Failed to send hello");
            return false;
        }

        const response = Memory.alloc(2);
        if (recv(sockfd, response, 2, 0) < 0) {
            console.error("SOCKS: Failed to receive server choice");
            return false;
        }

        if (response.readU8() !== 0x05 || response.add(1).readU8() !== 0x00) {
            console.error("SOCKS: Server rejected auth method");
            return false;
        }

        let req = [0x05, 0x01, 0x00]; // VER, CMD(CONNECT), RSV

        if (isIPv6) {
            req.push(0x04); // ATYP: IPv6
        } else { // IPv4
            req.push(0x01); // ATYP: IPv4
        }

        req.push(...targetHostBytes, (targetPort >> 8) & 0xff, targetPort & 0xff);
        const reqBuf = Memory.alloc(req.length).writeByteArray(req);

        if (send(sockfd, reqBuf, req.length, 0) < 0) {
            console.error("SOCKS: Failed to send connection request");
            return false;
        }

        const replyHeader = Memory.alloc(4);
        if (recv(sockfd, replyHeader, 4, 0) < 0) {
            console.error("SOCKS: Failed to receive reply header");
            return false;
        }

        const replyCode = replyHeader.add(1).readU8();
        if (replyCode !== 0x00) {
            console.error(`SOCKS: Server returned error code ${replyCode}`);
            return false;
        }

        const atyp = replyHeader.add(3).readU8();
        let remainingBytes = 0;
        if (atyp === 0x01) remainingBytes = 4 + 2; // IPv4 + port
        else if (atyp === 0x04) remainingBytes = 16 + 2; // IPv6 + port
        if (remainingBytes > 0) recv(sockfd, Memory.alloc(remainingBytes), remainingBytes, 0);

        return true;
    }
})();
/** [MODULE 3] Native TLS Interceptor */
/**************************************************************************************************
 *
 * Once we have captured traffic (once it's being sent to our proxy port) the next step is
 * to ensure any clients using TLS (HTTPS) trust our CA certificate, to allow us to intercept
 * encrypted connections successfully.
 *
 * This script does this, by defining overrides to hook BoringSSL (used by iOS 11+) and Cronet
 * (the Chromium network stack, used by some Android apps including TikTok). This is the primary
 * certificate trust mechanism for iOS, and only a niche addition for Android edge cases.
 *
 * The hooks defined here ensure that normal certificate validation is skipped, and instead any
 * TLS connection using our trusted CA is always trusted. In general use this disables both
 * normal & certificate-pinned TLS/HTTPS validation, so that all connections which use your CA
 * should always succeed.
 *
 * This does not completely disable TLS validation, but it does significantly relax it - it's
 * intended for use with the other scripts in this repo that ensure all traffic is routed directly
 * to your MitM proxy (generally on your local network). You probably don't want to use this for
 * any sensitive traffic sent over public/untrusted networks - it is difficult to intercept, and
 * any attacker would need a copy of the CA certificate you're using, but by its nature as a messy
 * hook around TLS internals it's probably not 100% secure.
 *
 * Since iOS 11 (2017) Apple has used BoringSSL internally to handle all TLS. This code
 * hooks low-level BoringSSL calls, to override all custom certificate validation completely.
 * https://nabla-c0d3.github.io/blog/2019/05/18/ssl-kill-switch-for-ios12/ to the general concept,
 * but note that this script goes further - reimplementing basic TLS cert validation, rather than
 * just returning OK blindly for all connections.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 *
 *************************************************************************************************/

const TARGET_LIBS = [
    { name: 'libboringssl.dylib', hooked: false }, // iOS primary TLS implementation
    { name: 'libsscronet.so', hooked: false }, // Cronet on Android
    { name: 'boringssl', hooked: false }, // Bundled by some apps e.g. TikTok on iOS
    { name: 'libssl.so', hooked: false }, // Native OpenSSL in Android
];

TARGET_LIBS.forEach((targetLib) => {
    waitForModule(targetLib.name, (targetModule) => {
        patchTargetLib(targetModule, targetLib.name);
        targetLib.hooked = true;
    });

    if (
        targetLib.name === 'libboringssl.dylib' &&
        Process.platform === 'darwin' &&
        !targetLib.hooked
    ) {
        // On iOS, we expect this to always work immediately, so print a warning if we
        // ever have to skip this TLS patching process.
        console.log(`\n !!! --- Could not load ${targetLib.name} to hook TLS --- !!!`);
    }
});

function patchTargetLib(targetModule, targetName) {
    // Get the peer certificates from an SSL pointer. Returns a pointer to a STACK_OF(CRYPTO_BUFFER)
    // which requires use of the next few methods below to actually access.
    // https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_get0_peer_certificates
    const SSL_get0_peer_certificates = new NativeFunction(
        targetModule.getExportByName('SSL_get0_peer_certificates'),
        'pointer', ['pointer']
    );

    // Stack methods:
    // https://commondatastorage.googleapis.com/chromium-boringssl-docs/stack.h.html
    const sk_num = new NativeFunction(
        targetModule.getExportByName('sk_num'),
        'size_t', ['pointer']
    );

    const sk_value = new NativeFunction(
        targetModule.getExportByName('sk_value'),
        'pointer', ['pointer', 'int']
    );

    // Crypto buffer methods:
    // https://commondatastorage.googleapis.com/chromium-boringssl-docs/pool.h.html
    const crypto_buffer_len = new NativeFunction(
        targetModule.getExportByName('CRYPTO_BUFFER_len'),
        'size_t', ['pointer']
    );

    const crypto_buffer_data = new NativeFunction(
        targetModule.getExportByName('CRYPTO_BUFFER_data'),
        'pointer', ['pointer']
    );

    const SSL_VERIFY_OK = 0x0;
    const SSL_VERIFY_INVALID = 0x1;

    // We cache the verification callbacks we create. In general (in testing, 100% of the time) the
    // 'real' callback is always the exact same address, so this is much more efficient than creating
    // a new callback every time.
    const verificationCallbackCache = {};

    const buildVerificationCallback = (realCallbackAddr) => {
        if (!verificationCallbackCache[realCallbackAddr]) {
            const realCallback = (realCallbackAddr && !realCallbackAddr.isNull())
                ? new NativeFunction(realCallbackAddr, 'int', ['pointer', 'pointer'])
                : () => SSL_VERIFY_INVALID;

            let pendingCheckThreads = new Set();

            const hookedCallback = new NativeCallback(function (ssl, out_alert) {
                let realResult = false; // False = not yet called, 0/1 = call result

                const threadId = Process.getCurrentThreadId();
                const alreadyHaveLock = pendingCheckThreads.has(threadId);

                // We try to have only one thread running these checks at a time, as parallel calls
                // here on the same underlying callback seem to crash in some specific scenarios
                while (pendingCheckThreads.size > 0 && !alreadyHaveLock) {
                    Thread.sleep(0.01);
                }
                pendingCheckThreads.add(threadId);

                if (targetName !== 'libboringssl.dylib') {
                    // Cronet assumes its callback is always called, and crashes if not. iOS's BoringSSL
                    // meanwhile seems to use some negative checks in its callback, and rejects the
                    // connection independently of the return value here if it's called with a bad cert.
                    // End result: we *only sometimes* proactively call the callback.
                    realResult = realCallback(ssl, out_alert);
                }

                // Extremely dumb certificate validation: we accept any chain where the *exact* CA cert
                // we were given is present. No flexibility for non-trivial cert chains, and no
                // validation beyond presence of the expected CA certificate. BoringSSL does do a
                // fair amount of essential validation independent of the certificate comparison
                // though, so some basics may be covered regardless (see tls13_process_certificate_verify).

                // This *intentionally* does not reject certs with the wrong hostname, expired CA
                // or leaf certs, and lots of other issues. This is significantly better than nothing,
                // but it is not production-ready TLS verification for general use in untrusted envs!

                const peerCerts = SSL_get0_peer_certificates(ssl);

                // Loop through every cert in the chain:
                for (let i = 0; i < sk_num(peerCerts); i++) {
                    // For each cert, check if it *exactly* matches our configured CA cert:
                    const cert = sk_value(peerCerts, i);
                    const certDataLength = crypto_buffer_len(cert).toNumber();

                    if (certDataLength !== CERT_DER.byteLength) continue;

                    const certPointer = crypto_buffer_data(cert);
                    const certData = new Uint8Array(certPointer.readByteArray(certDataLength));

                    if (certData.every((byte, j) => CERT_DER[j] === byte)) {
                        if (!alreadyHaveLock) pendingCheckThreads.delete(threadId);
                        return SSL_VERIFY_OK;
                    }
                }

                // No matched peer - fallback to the provided callback instead:
                if (realResult === false) { // Haven't called it yet
                    realResult = realCallback(ssl, out_alert);
                }

                if (!alreadyHaveLock) pendingCheckThreads.delete(threadId);
                return realResult;
            }, 'int', ['pointer','pointer']);

            verificationCallbackCache[realCallbackAddr] = hookedCallback;
        }

        return verificationCallbackCache[realCallbackAddr];
    };

    const customVerifyAddrs = [
        targetModule.findExportByName("SSL_set_custom_verify"),
        targetModule.findExportByName("SSL_CTX_set_custom_verify")
    ].filter(Boolean);

    customVerifyAddrs.forEach((set_custom_verify_addr) => {
        const set_custom_verify_fn = new NativeFunction(
            set_custom_verify_addr,
            'void', ['pointer', 'int', 'pointer']
        );

        // When this function is called, ignore the provided callback, and
        // configure our callback instead:
        Interceptor.replace(set_custom_verify_fn, new NativeCallback(function(ssl, mode, providedCallbackAddr) {
            set_custom_verify_fn(ssl, mode, buildVerificationCallback(providedCallbackAddr));
        }, 'void', ['pointer', 'int', 'pointer']));
    });

    if (customVerifyAddrs.length) {
        if (DEBUG_MODE) {
            console.log(`[+] Patched ${customVerifyAddrs.length} ${targetName} verification methods`);
        }
        console.log(`== Hooked native TLS lib ${targetName} ==`);
    } else {
        console.log(`\n !!! Hooking native TLS lib ${targetName} failed - no verification methods found`);
    }

    const get_psk_identity_addr = targetModule.findExportByName("SSL_get_psk_identity");
    if (get_psk_identity_addr) {
        // Hooking this is apparently required for some verification paths which check the
        // result is not 0x0. Any return value should work fine though.
        Interceptor.replace(get_psk_identity_addr, new NativeCallback(function(ssl) {
            return "PSK_IDENTITY_PLACEHOLDER";
        }, 'pointer', ['pointer']));
    } else if (customVerifyAddrs.length) {
        console.log(`Patched ${customVerifyAddrs.length} custom_verify methods, but couldn't find get_psk_identity`);
    }
}


/** [MODULE 4] Java Proxy Override */
/**************************************************************************************************
 *
 * The first step in intercepting HTTP & HTTPS traffic is to set the default proxy settings,
 * telling the app that all requests should be sent via our HTTP proxy.
 *
 * In this script, we set that up via a few different mechanisms, which cumulatively should
 * ensure that all connections are sent via the proxy, even if they attempt to use their
 * own custom proxy configurations to avoid this.
 *
 * Despite that, this still only covers well behaved apps - it's still possible for apps
 * to send network traffic directly if they're determined to do so, or if they're built
 * with a framework that does not do this by default (Flutter is notably in this category).
 * To handle those less tidy cases, we manually capture traffic to recognized target ports
 * in the native connect() hook script.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 *
 *************************************************************************************************/

Java.perform(() => {
    // Set default JVM system properties for the proxy address. Notably these are used
    // to initialize WebView configuration.
    Java.use('java.lang.System').setProperty('http.proxyHost', PROXY_HOST);
    Java.use('java.lang.System').setProperty('http.proxyPort', PROXY_PORT.toString());
    Java.use('java.lang.System').setProperty('https.proxyHost', PROXY_HOST);
    Java.use('java.lang.System').setProperty('https.proxyPort', PROXY_PORT.toString());

    Java.use('java.lang.System').clearProperty('http.nonProxyHosts');
    Java.use('java.lang.System').clearProperty('https.nonProxyHosts');

    // Some Android internals attempt to reset these settings to match the device configuration.
    // We block that directly here:
    const controlledSystemProperties = [
        'http.proxyHost',
        'http.proxyPort',
        'https.proxyHost',
        'https.proxyPort',
        'http.nonProxyHosts',
        'https.nonProxyHosts'
    ];
    Java.use('java.lang.System').clearProperty.implementation = function (property) {
        if (controlledSystemProperties.includes(property)) {
            if (DEBUG_MODE) console.log(`Ignoring attempt to clear ${property} system property`);
            return this.getProperty(property);
        }
        return this.clearProperty(...arguments);
    }
    Java.use('java.lang.System').setProperty.implementation = function (property) {
        if (controlledSystemProperties.includes(property)) {
            if (DEBUG_MODE) console.log(`Ignoring attempt to override ${property} system property`);
            return this.getProperty(property);
        }
        return this.setProperty(...arguments);
    }

    // Configure the app's proxy directly, via the app connectivity manager service:
    const ConnectivityManager = Java.use('android.net.ConnectivityManager');
    const ProxyInfo = Java.use('android.net.ProxyInfo');
    ConnectivityManager.getDefaultProxy.implementation = () => ProxyInfo.$new(PROXY_HOST, PROXY_PORT, '');
    // (Not clear if this works 100% - implying there are ConnectivityManager subclasses handling this)

    console.log(`== Proxy system configuration overridden to ${PROXY_HOST}:${PROXY_PORT} ==`);

    // Configure the proxy indirectly, by overriding the return value for all ProxySelectors everywhere:
    const Collections = Java.use('java.util.Collections');
    const ProxyType = Java.use('java.net.Proxy$Type');
    const InetSocketAddress = Java.use('java.net.InetSocketAddress');
    const ProxyCls = Java.use('java.net.Proxy'); // 'Proxy' is reserved in JS

    const targetProxy = ProxyCls.$new(
        ProxyType.HTTP.value,
        InetSocketAddress.$new(PROXY_HOST, PROXY_PORT)
    );
    const getTargetProxyList = () => Collections.singletonList(targetProxy);

    const ProxySelector = Java.use('java.net.ProxySelector');

    // Find every implementation of ProxySelector by quickly scanning method signatures, and
    // then checking whether each match actually implements java.net.ProxySelector:
    const proxySelectorClasses = Java.enumerateMethods('*!select(java.net.URI): java.util.List/s')
        .flatMap((matchingLoader) => matchingLoader.classes
            .map((classData) => Java.use(classData.name))
            .filter((Cls) => ProxySelector.class.isAssignableFrom(Cls.class))
        );

    // Replace the 'select' of every implementation, so they all send traffic to us:
    proxySelectorClasses.forEach(ProxySelectorCls => {
        if (DEBUG_MODE) {
            console.log('Rewriting', ProxySelectorCls.toString());
        }
        ProxySelectorCls.select.implementation = () => getTargetProxyList()
    });

    console.log(`== Proxy configuration overridden to ${PROXY_HOST}:${PROXY_PORT} ==`);
});


/** [MODULE 5] Dynamic Certificate Injection */
/**************************************************************************************************
 *
 * Once we have captured traffic (once it's being sent to our proxy port) the next step is
 * to ensure any clients using TLS (HTTPS) trust our CA certificate, to allow us to intercept
 * encrypted connections successfully.
 *
 * This script does so by attaching to the internals of Conscrypt (the Android SDK's standard
 * TLS implementation) and pre-adding our certificate to the 'already trusted' cache, so that
 * future connections trust it implicitly. This ensures that all normal uses of Android APIs
 * for HTTPS & TLS will allow interception.
 *
 * This does not handle all standalone certificate pinning techniques - where the application
 * actively rejects certificates that are trusted by default on the system. That's dealt with
 * in the separate certificate unpinning script.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 *
 *************************************************************************************************/

Java.perform(() => {
    // First, we build a JVM representation of our certificate:
    const String = Java.use("java.lang.String");
    const ByteArrayInputStream = Java.use('java.io.ByteArrayInputStream');
    const CertFactory = Java.use('java.security.cert.CertificateFactory');

    let cert;
    try {
        const certFactory = CertFactory.getInstance("X.509");
        const certBytes = String.$new(CERT_PEM).getBytes();
        cert = certFactory.generateCertificate(ByteArrayInputStream.$new(certBytes));
    } catch (e) {
        console.error('Could not parse provided certificate PEM!');
        console.error(e);
        Java.use('java.lang.System').exit(1);
    }

    // Then we hook TrustedCertificateIndex. This is used for caching known trusted certs within Conscrypt -
    // by prepopulating all instances, we ensure that all TrustManagerImpls (and potentially other
    // things) automatically trust our certificate specifically (without disabling validation entirely).
    // This should apply to Android v7+ - previous versions used SSLContext & X509TrustManager.
    [
        'com.android.org.conscrypt.TrustedCertificateIndex',
        'org.conscrypt.TrustedCertificateIndex', // Might be used (com.android is synthetic) - unclear
        'org.apache.harmony.xnet.provider.jsse.TrustedCertificateIndex' // Used in Apache Harmony version of Conscrypt
    ].forEach((TrustedCertificateIndexClassname, i) => {
        let TrustedCertificateIndex;
        try {
            TrustedCertificateIndex = Java.use(TrustedCertificateIndexClassname);
        } catch (e) {
            if (i === 0) {
                throw new Error(`${TrustedCertificateIndexClassname} not found - could not inject system certificate`);
            } else {
                // Other classnames are optional fallbacks
                if (DEBUG_MODE) {
                    console.log(`[ ] Skipped cert injection for ${TrustedCertificateIndexClassname} (not present)`);
                }
                return;
            }
        }

        TrustedCertificateIndex.$init.overloads.forEach((overload) => {
            overload.implementation = function () {
                this.$init(...arguments);
                // Index our cert as already trusted, right from the start:
                this.index(cert);
            }
        });

        TrustedCertificateIndex.reset.overloads.forEach((overload) => {
            overload.implementation = function () {
                const result = this.reset(...arguments);
                // Index our cert in here again, since the reset removes it:
                this.index(cert);
                return result;
            };
        });

        if (DEBUG_MODE) console.log(`[+] Injected cert into ${TrustedCertificateIndexClassname}`);
    });

    // This effectively adds us to the system certs, and also defeats quite a bit of basic certificate
    // pinning too! It auto-trusts us in any implementation that uses TrustManagerImpl (Conscrypt) as
    // the underlying cert checking component.

    console.log('== System certificate trust injected ==');
});
/** [MODULE 6] Universal Java Unpinning */
/**************************************************************************************************
 *
 * This script defines a large set of targeted certificate unpinning hooks: matching specific
 * methods in certain classes, and transforming their behaviour to ensure that restrictions to
 * TLS trust are disabled.
 *
 * This does not disable TLS protections completely - each hook is designed to disable only
 * *additional* restrictions, and to explicitly trust the certificate provided as CERT_PEM in the
 * config.js configuration file, preserving normal TLS protections wherever possible, even while
 * allowing for controlled MitM of local traffic.
 *
 * The file consists of a few general-purpose methods, then a data structure declaratively
 * defining the classes & methods to match, and how to transform them, and then logic at the end
 * which uses this data structure, applying the transformation for each found match to the
 * target process.
 *
 * For more details on what was matched, and log output when each hooked method is actually used,
 * enable DEBUG_MODE in config.js, and watch the Frida output after running this script.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 *
 *************************************************************************************************/

function buildX509CertificateFromBytes(certBytes) {
    const ByteArrayInputStream = Java.use('java.io.ByteArrayInputStream');
    const CertFactory = Java.use('java.security.cert.CertificateFactory');
    const certFactory = CertFactory.getInstance("X.509");
    return certFactory.generateCertificate(ByteArrayInputStream.$new(certBytes));
}

function getCustomTrustManagerFactory() {
    // This is the one X509Certificate that we want to trust. No need to trust others (we should capture
    // _all_ TLS traffic) and risky to trust _everything_ (risks interception between device & proxy, or
    // worse: some traffic being unintercepted & sent as HTTPS with TLS effectively disabled over the
    // real web - potentially exposing auth keys, private data and all sorts).
    const certBytes = Java.use("java.lang.String").$new(CERT_PEM).getBytes();
    const trustedCACert = buildX509CertificateFromBytes(certBytes);

    // Build a custom TrustManagerFactory with a KeyStore that trusts only this certificate:

    const KeyStore = Java.use("java.security.KeyStore");
    const keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null);
    keyStore.setCertificateEntry("ca", trustedCACert);

    const TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
    const customTrustManagerFactory = TrustManagerFactory.getInstance(
        TrustManagerFactory.getDefaultAlgorithm()
    );
    customTrustManagerFactory.init(keyStore);

    return customTrustManagerFactory;
}

function getCustomX509TrustManager() {
    const customTrustManagerFactory = getCustomTrustManagerFactory();
    const trustManagers = customTrustManagerFactory.getTrustManagers();

    const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');

    const x509TrustManager = trustManagers.find((trustManager) => {
        return trustManager.class.isAssignableFrom(X509TrustManager.class);
    });

    // We have to cast it explicitly before Frida will allow us to use the X509 methods:
    return Java.cast(x509TrustManager, X509TrustManager);
}

// Some standard hook replacements for various cases:
const NO_OP = () => {};
const RETURN_TRUE = () => true;
const CHECK_OUR_TRUST_MANAGER_ONLY = () => {
    const trustManager = getCustomX509TrustManager();
    return (certs, authType) => {
        trustManager.checkServerTrusted(certs, authType);
    };
};

const PINNING_FIXES = {
    // --- Native HttpsURLConnection

    'javax.net.ssl.HttpsURLConnection': [
        {
            methodName: 'setDefaultHostnameVerifier',
            replacement: () => NO_OP
        },
        {
            methodName: 'setSSLSocketFactory',
            replacement: () => NO_OP
        },
        {
            methodName: 'setHostnameVerifier',
            replacement: () => NO_OP
        },
    ],

    // --- Native SSLContext

    'javax.net.ssl.SSLContext': [
        {
            methodName: 'init',
            overload: ['[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'],
            replacement: (targetMethod) => {
                const customTrustManagerFactory = getCustomTrustManagerFactory();

                // When constructor is called, replace the trust managers argument:
                return function (keyManager, _providedTrustManagers, secureRandom) {
                    return targetMethod.call(this,
                        keyManager,
                        customTrustManagerFactory.getTrustManagers(), // Override their trust managers
                        secureRandom
                    );
                }
            }
        }
    ],

    // --- Native Conscrypt CertPinManager

    'com.android.org.conscrypt.CertPinManager': [
        {
            methodName: 'isChainValid',
            replacement: () => RETURN_TRUE
        },
        {
            methodName: 'checkChainPinning',
            replacement: () => NO_OP
        }
    ],

    // --- Native Conscrypt CertificateTransparency

    'com.android.org.conscrypt.ct.CertificateTransparency': [
        {
            methodName: 'checkCT',
            replacement: () => NO_OP
        }
    ],

    // --- Native pinning configuration loading (used for configuration by many libraries)

    'android.security.net.config.NetworkSecurityConfig': [
        {
            methodName: '$init',
            overload: '*',
            replacement: (targetMethod) => {
                const PinSet = Java.use('android.security.net.config.PinSet');
                const EMPTY_PINSET = PinSet.EMPTY_PINSET.value;
                return function () {
                    // Always ignore the 2nd 'pins' PinSet argument entirely:
                    arguments[2] = EMPTY_PINSET;
                    targetMethod.call(this, ...arguments);
                }
            }
        }
    ],

    // --- Native HostnameVerification override (n.b. Android contains its own vendored OkHttp v2!)

    'com.android.okhttp.internal.tls.OkHostnameVerifier': [
        {
            methodName: 'verify',
            overload: [
                'java.lang.String',
                'javax.net.ssl.SSLSession'
            ],
            replacement: (targetMethod) => {
                // Our trust manager - this trusts *only* our extra CA
                const trustManager = getCustomX509TrustManager();

                return function (hostname, sslSession) {
                    try {
                        const certs = sslSession.getPeerCertificates();

                        // https://stackoverflow.com/a/70469741/68051
                        const authType = "RSA";

                        // This throws if the certificate isn't trusted (i.e. if it's
                        // not signed by our extra CA specifically):
                        trustManager.checkServerTrusted(certs, authType);

                        // If the cert is from our CA, great! Skip hostname checks entirely.
                        return true;
                    } catch (e) {} // Ignore errors and fallback to default behaviour

                    // We fallback to ensure that connections with other CAs (e.g. direct
                    // connections allowed past the proxy) validate as normal.
                    return targetMethod.call(this, ...arguments);
                }
            }
        }
    ],

    'com.android.okhttp.Address': [
        {
            methodName: '$init',
            overload: [
                'java.lang.String',
                'int',
                'com.android.okhttp.Dns',
                'javax.net.SocketFactory',
                'javax.net.ssl.SSLSocketFactory',
                'javax.net.ssl.HostnameVerifier',
                'com.android.okhttp.CertificatePinner',
                'com.android.okhttp.Authenticator',
                'java.net.Proxy',
                'java.util.List',
                'java.util.List',
                'java.net.ProxySelector'
            ],
            replacement: (targetMethod) => {
                const defaultHostnameVerifier = Java.use("com.android.okhttp.internal.tls.OkHostnameVerifier")
                    .INSTANCE.value;
                const defaultCertPinner = Java.use("com.android.okhttp.CertificatePinner")
                    .DEFAULT.value;

                return function () {
                    // Override arguments, to swap any custom check params (widely used
                    // to add stricter rules to TLS verification) with the defaults instead:
                    arguments[5] = defaultHostnameVerifier;
                    arguments[6] = defaultCertPinner;

                    targetMethod.call(this, ...arguments);
                }
            }
        },
        // Almost identical patch, but for Nougat and older. In these versions, the DNS argument
        // isn't passed here, so the arguments to patch changes slightly:
        {
            methodName: '$init',
            overload: [
                'java.lang.String',
                'int',
                // No DNS param
                'javax.net.SocketFactory',
                'javax.net.ssl.SSLSocketFactory',
                'javax.net.ssl.HostnameVerifier',
                'com.android.okhttp.CertificatePinner',
                'com.android.okhttp.Authenticator',
                'java.net.Proxy',
                'java.util.List',
                'java.util.List',
                'java.net.ProxySelector'
            ],
            replacement: (targetMethod) => {
                const defaultHostnameVerifier = Java.use("com.android.okhttp.internal.tls.OkHostnameVerifier")
                    .INSTANCE.value;
                const defaultCertPinner = Java.use("com.android.okhttp.CertificatePinner")
                    .DEFAULT.value;

                return function () {
                    // Override arguments, to swap any custom check params (widely used
                    // to add stricter rules to TLS verification) with the defaults instead:
                    arguments[4] = defaultHostnameVerifier;
                    arguments[5] = defaultCertPinner;

                    targetMethod.call(this, ...arguments);
                }
            }
        }
    ],

    // --- OkHttp v3

    'okhttp3.CertificatePinner': [
        {
            methodName: 'check',
            overload: ['java.lang.String', 'java.util.List'],
            replacement: () => NO_OP
        },
        {
            methodName: 'check',
            overload: ['java.lang.String', 'java.security.cert.Certificate'],
            replacement: () => NO_OP
        },
        {
            methodName: 'check',
            overload: ['java.lang.String', '[Ljava.security.cert.Certificate;'],
            replacement: () => NO_OP
        },
        {
            methodName: 'check$okhttp',
            replacement: () => NO_OP
        },
    ],

    // --- SquareUp OkHttp (< v3)

    'com.squareup.okhttp.CertificatePinner': [
        {
            methodName: 'check',
            overload: ['java.lang.String', 'java.security.cert.Certificate'],
            replacement: () => NO_OP
        },
        {
            methodName: 'check',
            overload: ['java.lang.String', 'java.util.List'],
            replacement: () => NO_OP
        }
    ],

    // --- Trustkit (https://github.com/datatheorem/TrustKit-Android/)

    'com.datatheorem.android.trustkit.pinning.PinningTrustManager': [
        {
            methodName: 'checkServerTrusted',
            replacement: CHECK_OUR_TRUST_MANAGER_ONLY
        }
    ],

    // --- Appcelerator (https://github.com/tidev/appcelerator.https)

    'appcelerator.https.PinningTrustManager': [
        {
            methodName: 'checkServerTrusted',
            replacement: CHECK_OUR_TRUST_MANAGER_ONLY
        }
    ],

    // --- PhoneGap sslCertificateChecker (https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin)

    'nl.xservices.plugins.sslCertificateChecker': [
        {
            methodName: 'execute',
            overload: ['java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext'],
            replacement: () => (_action, _args, context) => {
                context.success("CONNECTION_SECURE");
                return true;
            }
            // This trusts _all_ certs, but that's fine - this is used for checks of independent test
            // connections, rather than being a primary mechanism to secure the app's TLS connections.
        }
    ],

    // --- IBM WorkLight

    'com.worklight.wlclient.api.WLClient': [
        {
            methodName: 'pinTrustedCertificatePublicKey',
            getMethod: (WLClientCls) => WLClientCls.getInstance().pinTrustedCertificatePublicKey,
            overload: '*'
        }
    ],

    'com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning': [
        {
            methodName: 'verify',
            overload: '*',
            replacement: () => NO_OP
        }
        // This covers at least 4 commonly used WorkLight patches. Oddly, most sets of hooks seem
        // to return true for 1/4 cases, which must be wrong (overloads must all have the same
        // return type) but also it's very hard to find any modern (since 2017) references to this
        // class anywhere including WorkLight docs, so it may no longer be relevant anyway.
    ],

    'com.worklight.androidgap.plugin.WLCertificatePinningPlugin': [
        {
            methodName: 'execute',
            overload: '*',
            replacement: () => RETURN_TRUE
        }
    ],

    // --- CWAC-Netsecurity (unofficial back-port pinner for Android<4.2) CertPinManager

    'com.commonsware.cwac.netsecurity.conscrypt.CertPinManager': [
        {
            methodName: 'isChainValid',
            overload: '*',
            replacement: () => RETURN_TRUE
        }
    ],

    // --- Netty

    'io.netty.handler.ssl.util.FingerprintTrustManagerFactory': [
        {
            methodName: 'checkTrusted',
            replacement: () => NO_OP
        }
    ],

    // --- Cordova / PhoneGap Advanced HTTP Plugin (https://github.com/silkimen/cordova-plugin-advanced-http)

    // Modern version:
    'com.silkimen.cordovahttp.CordovaServerTrust': [
        {
            methodName: '$init',
            replacement: (targetMethod) => function () {
                // Ignore any attempts to set trust to 'pinned'. Default settings will trust
                // our cert because of the separate system-certificate injection step.
                if (arguments[0] === 'pinned') {
                    arguments[0] = 'default';
                }

                return targetMethod.call(this, ...arguments);
            }
        }
    ],

    // --- Appmattus Cert Transparency (https://github.com/appmattus/certificatetransparency/)

    'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyHostnameVerifier': [
        {
            methodName: 'verify',
            replacement: () => RETURN_TRUE
            // This is not called unless the cert passes basic trust checks, so it's safe to blindly accept.
        }
    ],

    'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor': [
        {
            methodName: 'intercept',
            replacement: () => (a) => a.proceed(a.request())
            // This is not called unless the cert passes basic trust checks, so it's safe to blindly accept.
        }
    ],

    'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager': [
        {
            methodName: 'checkServerTrusted',
            overload: ['[Ljava.security.cert.X509Certificate;', 'java.lang.String'],
            replacement: CHECK_OUR_TRUST_MANAGER_ONLY,
            methodName: 'checkServerTrusted',
            overload: ['[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String'],
            replacement: () => {
                const trustManager = getCustomX509TrustManager();
                return (certs, authType, _hostname) => {
                    // We ignore the hostname - if the certs are good (i.e they're ours), then the
                    // whole chain is good to go.
                    trustManager.checkServerTrusted(certs, authType);
                    return Java.use('java.util.Arrays').asList(certs);
                };
            }
        }
    ]

};

const getJavaClassIfExists = (clsName) => {
    try {
        return Java.use(clsName);
    } catch {
        return undefined;
    }
}

Java.perform(function () {
    if (DEBUG_MODE) console.log('\n    === Disabling all recognized unpinning libraries ===');

    const classesToPatch = Object.keys(PINNING_FIXES);

    classesToPatch.forEach((targetClassName) => {
        const TargetClass = getJavaClassIfExists(targetClassName);
        if (!TargetClass) {
            // We skip patches for any classes that don't seem to be present. This is common
            // as not all libraries we handle are necessarily used.
            if (DEBUG_MODE) console.log(`[ ] ${targetClassName} *`);
            return;
        }

        const patches = PINNING_FIXES[targetClassName];

        let patchApplied = false;

        patches.forEach(({ methodName, getMethod, overload, replacement }) => {
            const namedTargetMethod = getMethod
                ? getMethod(TargetClass)
                : TargetClass[methodName];

            const methodDescription = `${methodName}${
                overload === '*'
                    ? '(*)'
                : overload
                    ? '(' + overload.map((argType) => {
                        // Simplify arg names to just the class name for simpler logs:
                        const argClassName = argType.split('.').slice(-1)[0];
                        if (argType.startsWith('[L')) return `${argClassName}[]`;
                        else return argClassName;
                    }).join(', ') + ')'
                // No overload:
                    : ''
            }`

            let targetMethodImplementations = [];
            try {
                if (namedTargetMethod) {
                    if (!overload) {
                            // No overload specified
                        targetMethodImplementations = [namedTargetMethod];
                    } else if (overload === '*') {
                        // Targetting _all_ overloads
                        targetMethodImplementations = namedTargetMethod.overloads;
                    } else {
                        // Or targetting a specific overload:
                        targetMethodImplementations = [namedTargetMethod.overload(...overload)];
                    }
                }
            } catch (e) {
                // Overload not present
            }


            // We skip patches for any methods that don't seem to be present. This is rarer, but does
            // happen due to methods that only appear in certain library versions or whose signatures
            // have changed over time.
            if (targetMethodImplementations.length === 0) {
                if (DEBUG_MODE) console.log(`[ ] ${targetClassName} ${methodDescription}`);
                return;
            }

            targetMethodImplementations.forEach((targetMethod, i) => {
                const patchName = `${targetClassName} ${methodDescription}${
                    targetMethodImplementations.length > 1 ? ` (${i})` : ''
                }`;

                try {
                    const newImplementation = replacement(targetMethod);
                    if (DEBUG_MODE) {
                        // Log each hooked method as it's called:
                        targetMethod.implementation = function () {
                            console.log(` => ${patchName}`);
                            return newImplementation.apply(this, arguments);
                        }
                    } else {
                        targetMethod.implementation = newImplementation;
                    }

                    if (DEBUG_MODE) console.log(`[+] ${patchName}`);
                    patchApplied = true;
                } catch (e) {
                    // In theory, errors like this should never happen - it means the patch is broken
                    // (e.g. some dynamic patch building fails completely)
                    console.error(`[!] ERROR: ${patchName} failed: ${e}`);
                }
            })
        });

        if (!patchApplied) {
            console.warn(`[!] Matched class ${targetClassName} but could not patch any methods`);
        }
    });

    console.log('== Certificate unpinning completed ==');
});

/** [MODULE 7] Java Unpinning Fallback */
/**************************************************************************************************
 *
 * Once we've set up the configuration and certificate, and then disabled all the pinning
 * techniques we're aware of, we add one last touch: a fallback hook, designed to spot and handle
 * unknown unknowns.
 *
 * This can also be useful for heavily obfuscated apps, where 3rd party libraries are obfuscated
 * sufficiently that our hooks no longer recognize the methods we care about.
 *
 * To handle this, we watch for methods that throw known built-in TLS errors (these are *very*
 * widely used, and always recognizable as they're defined natively), and then subsequently patch
 * them for all future calls. Whenever a method throws this, we attempt to recognize it from
 * signatures alone, and automatically hook it.
 *
 * These are very much a fallback! They might not work! They almost certainly won't work on the
 * first request, so applications will see at least one failure. Even when they fail though, they
 * will at least log the method that's failing, so this works well as a starting point for manual
 * reverse engineering. If this does fail and cause problems, you may want to skip this script
 * and use only the known-good patches provided elsewhere.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 *
 *************************************************************************************************/

// Capture the full fields or methods from a Frida class reference via JVM reflection:
const getFields = (cls) => getFridaValues(cls, cls.class.getDeclaredFields());
const getMethods = (cls) => getFridaValues(cls, cls.class.getDeclaredMethods());

// Take a Frida class + JVM reflection result, and turn it into a clear list
// of names -> Frida values (field or method references)
const getFridaValues = (cls, values) => values.map((value) =>
    [value.getName(), cls[value.getName()]]
);

Java.perform(function () {
    try {
        const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        const defaultTrustManager = getCustomX509TrustManager(); // Defined in the unpinning script
        const certBytes = Java.use("java.lang.String").$new(CERT_PEM).getBytes();
        const trustedCACert = buildX509CertificateFromBytes(certBytes); // Ditto

        const isX509TrustManager = (cls, methodName) =>
            methodName === 'checkServerTrusted' &&
            X509TrustManager.class.isAssignableFrom(cls.class);

        // There are two standard methods that X509TM implementations might override. We confirm we're
        // matching the methods we expect by double-checking against the argument types:
        const BASE_METHOD_ARGUMENTS = [
            '[Ljava.security.cert.X509Certificate;',
            'java.lang.String'
        ];
        const EXTENDED_METHOD_ARGUMENTS = [
            '[Ljava.security.cert.X509Certificate;',
            'java.lang.String',
            'java.lang.String'
        ];

        const isOkHttpCheckMethod = (errorMessage, method) =>
            errorMessage.startsWith("Certificate pinning failure!" + "\n  Peer certificate chain:") &&
            method.argumentTypes.length === 2 &&
            method.argumentTypes[0].className === 'java.lang.String';

        const isAppmattusOkHttpInterceptMethod = (errorMessage, method) => {
            if (errorMessage !== 'Certificate transparency failed') return;

            // Takes a single OkHttp chain argument:
            if (method.argumentTypes.length !== 1) return;

            // The method must take an Interceptor.Chain, for which we need to
            // call chain.proceed(chain.request()) to return a Response type.
            // To do that, we effectively pattern match our way through all the
            // related types to work out what's what:

            const chainType = Java.use(method.argumentTypes[0].className);
            const responseTypeName = method.returnType.className;

            const matchedChain = matchOkHttpChain(chainType, responseTypeName);
            return !!matchedChain;
        };

        const isMetaPinningMethod = (errorMessage, method) =>
            method.argumentTypes.length === 1 &&
            method.argumentTypes[0].className === 'java.util.List' &&
            method.returnType.className === 'void' &&
            errorMessage.includes('pinning error');

        const matchOkHttpChain = (cls, expectedReturnTypeName) => {
            // Find the chain.proceed() method:
            const methods = getMethods(cls);
            const matchingMethods = methods.filter(([_, method]) =>
                method.returnType.className === expectedReturnTypeName
            );
            if (matchingMethods.length !== 1) return;

            const [proceedMethodName, proceedMethod] = matchingMethods[0];
            if (proceedMethod.argumentTypes.length !== 1) return;

            const argumentTypeName = proceedMethod.argumentTypes[0].className;

            // Find the chain.request private field (.request() getter can be
            // optimized out, so we read the field directly):
            const fields = getFields(cls);
            const matchingFields = fields.filter(([_, field]) =>
                field.fieldReturnType?.className === argumentTypeName
            );
            if (matchingFields.length !== 1) return;

            const [requestFieldName] = matchingFields[0];

            return {
                proceedMethodName,
                requestFieldName
            };
        };

        const buildUnhandledErrorPatcher = (errorClassName, originalConstructor) => {
            return function (errorArg) {
                try {
                    console.log('\n !!! --- Unexpected TLS failure --- !!!');

                    // This may be a message, or an cause, or plausibly maybe other types? But
                    // stringifying gives something consistently message-shaped, so that'll do.
                    const errorMessage = errorArg?.toString() ?? '';

                    // Parse the stack trace to work out who threw this error:
                    const stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                    const exceptionStackIndex = stackTrace.findIndex(stack =>
                        stack.getClassName() === errorClassName
                    );
                    const callingFunctionStack = stackTrace[exceptionStackIndex + 1];

                    const className = callingFunctionStack.getClassName();
                    const methodName = callingFunctionStack.getMethodName();

                    const errorTypeName = errorClassName.split('.').slice(-1)[0];
                    console.log(`      ${errorTypeName}: ${errorMessage}`);
                    console.log(`      Thrown by ${className}->${methodName}`);

                    const callingClass = Java.use(className);
                    const callingMethod = callingClass[methodName];

                    callingMethod.overloads.forEach((failingMethod) => {
                        if (failingMethod.implementation) {
                            console.warn('      Already patched - but still failing!')
                            return; // Already patched by Frida - skip it
                        }

                        // Try to spot known methods (despite obfuscation) and disable them:
                        if (isOkHttpCheckMethod(errorMessage, failingMethod)) {
                            // See okhttp3.CertificatePinner patches in unpinning script:
                            failingMethod.implementation = () => {
                                if (DEBUG_MODE) console.log(` => Fallback OkHttp patch`);
                            };
                            console.log(`      [+] ${className}->${methodName} (fallback OkHttp patch)`);
                        } else if (isAppmattusOkHttpInterceptMethod(errorMessage, failingMethod)) {
                            // See Appmattus CertificateTransparencyInterceptor patch in unpinning script:
                            const chainType = Java.use(failingMethod.argumentTypes[0].className);
                            const responseTypeName = failingMethod.returnType.className;
                            const okHttpChain = matchOkHttpChain(chainType, responseTypeName);
                            failingMethod.implementation = (chain) => {
                                if (DEBUG_MODE) console.log(` => Fallback Appmattus+OkHttp patch`);
                                const proceed = chain[okHttpChain.proceedMethodName].bind(chain);
                                const request = chain[okHttpChain.requestFieldName].value;
                                return proceed(request);
                            };
                            console.log(`      [+] ${className}->${methodName} (fallback Appmattus+OkHttp patch)`);
                        } else if (isX509TrustManager(callingClass, methodName)) {
                            const argumentTypes = failingMethod.argumentTypes.map(t => t.className);
                            const returnType = failingMethod.returnType.className;

                            if (
                                argumentTypes.length === 2 &&
                                argumentTypes.every((t, i) => t === BASE_METHOD_ARGUMENTS[i]) &&
                                returnType === 'void'
                            ) {
                                // For the base method, just check against the default:
                                failingMethod.implementation = (certs, authType) => {
                                    if (DEBUG_MODE) console.log(` => Fallback X509TrustManager patch of ${
                                        className
                                    } base method`);

                                    const defaultTrustManager = getCustomX509TrustManager(); // Defined in the unpinning script
                                    defaultTrustManager.checkServerTrusted(certs, authType);
                                };
                                console.log(`      [+] ${className}->${methodName} (fallback X509TrustManager base patch)`);
                            } else if (
                                argumentTypes.length === 3 &&
                                argumentTypes.every((t, i) => t === EXTENDED_METHOD_ARGUMENTS[i]) &&
                                returnType === 'java.util.List'
                            ) {
                                // For the extended method, we just ignore the hostname, and if the certs are good
                                // (i.e they're ours), then we say the whole chain is good to go:
                                failingMethod.implementation = function (certs, authType, _hostname) {
                                    if (DEBUG_MODE) console.log(` => Fallback X509TrustManager patch of ${
                                        className
                                    } extended method`);

                                    try {
                                        defaultTrustManager.checkServerTrusted(certs, authType);
                                    } catch (e) {
                                        console.error('Default TM threw:', e);
                                    }
                                    return Java.use('java.util.Arrays').asList(certs);
                                };
                                console.log(`      [+] ${className}->${methodName} (fallback X509TrustManager ext patch)`);
                            } else {
                                console.warn(`      [ ] Skipping unrecognized checkServerTrusted signature in class ${
                                    callingClass.class.getName()
                                }`);
                            }
                        } else if (isMetaPinningMethod(errorMessage, failingMethod)) {
                            failingMethod.implementation = function (certs) {
                                if (DEBUG_MODE) console.log(` => Fallback patch for meta proxygen pinning`);
                                for (const cert of certs.toArray()) {
                                    if (cert.equals(trustedCACert)) {
                                        return; // Our own cert - all good
                                    }
                                }

                                if (DEBUG_MODE) {
                                    console.warn(' Meta unpinning fallback found only untrusted certificates');
                                }
                                // Fall back to normal logic, in case of passthrough or similar
                                return failingMethod.call(this, certs);
                            }

                            console.log(`      [+] ${className}->${methodName} (Meta proxygen pinning fallback patch)`);
                        } else {
                            console.error('      [ ] Unrecognized TLS error - this must be patched manually');
                            return;
                            // Later we could try to cover other cases here - automatically recognizing other
                            // OkHttp interceptors for example, or potentially other approaches, but we need
                            // to do so carefully to avoid disabling TLS checks entirely.
                        }
                    });
                } catch (e) {
                    console.log('      [ ] Failed to automatically patch failure');
                    console.warn(e);
                }

                return originalConstructor.call(this, ...arguments);
            }
        };

        // These are the exceptions we watch for and attempt to auto-patch out after they're thrown:
        [
            'javax.net.ssl.SSLPeerUnverifiedException',
            'java.security.cert.CertificateException'
        ].forEach((errorClassName) => {
            const ErrorClass = Java.use(errorClassName);
            ErrorClass.$init.overloads.forEach((overload) => {
                overload.implementation = buildUnhandledErrorPatcher(
                    errorClassName,
                    overload
                );
            });
        })

        console.log('== Unpinning fallback auto-patcher installed ==');
    } catch (err) {
        console.error(err);
        console.error(' !!! --- Unpinning fallback auto-patcher installation failed --- !!!');
    }

});
/** [MODULE 8] Flutter Engine Bypass */
/**************************************************************************************************
 *
 * This script hooks Flutter internal certificate handling, to trust our certificate (and ignore
 * any custom certificate validation - e.g. pinning libraries) for all TLS connections.
 *
 * Unfortunately Flutter is shipped as native code with no exported symbols, so we have to do this
 * by matching individual function signatures by known patterns of assembly instructions. In
 * some cases, this goes further and uses larger functions as anchors - allowing us to find the
 * very short functions correctly, where the patterns would otherwise have false positives.
 *
 * The patterns here have been generated from every non-patch release of Flutter from v2.0.0
 * to v3.32.0 (the latest at the time of writing). They may need updates for new versions
 * in future.
 *
 * Currently this is limited to just Android, but in theory this can be expanded to iOS and
 * desktop platforms in future.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 *
 *************************************************************************************************/

(() => {
    const PATTERNS = {
    "android/x64": {
        "dart::bin::SSLCertContext::CertificateCallback": {
            "signatures": [
                "41 57 41 56 53 48 83 ec 10 b8 01 00 00 00 83 ff 01 0f 84 ?? ?? ?? ?? 48 89 f3",
                "41 57 41 56 41 54 53 48 83 ec 18 b8 01 00 00 00 83 ff 01 0f 84 ?? ?? ?? ?? 48 89 f3"
            ]
        },
        "X509_STORE_CTX_get_current_cert": {
            "signatures": [
                "48 8b 47 50 c3",
                "48 8b 47 60 c3",
                "48 8b 87 a8 00 00 00 c3",
                "48 8b 87 b8 00 00 00 c3"
            ],
            "anchor": "dart::bin::SSLCertContext::CertificateCallback"
        },
        "bssl::x509_to_buffer": {
            "signatures": [
                "41 56 53 50 48 89 f0 48 89 fb 48 89 e6 48 83 26 00 48 89 c7 e8 ?? ?? ?? ?? 85 c0 7e 1b",
                "53 48 83 ec 10 48 89 f0 48 89 fb 48 8d 74 24 08 48 83 26 00 48 89 c7 e8 ?? ?? ?? ?? 85 c0",
                "41 56 53 48 83 ec 18 48 89 f0 48 89 fb 48 8d 74 24 08 48 83 26 00 48 89 c7 e8",
                "41 56 53 48 83 ec 18 48 89 f0 49 89 fe 48 8d 74 24 08 48 83 26 00 48 89 c7 e8",
                "41 57 41 56 53 48 83 ec 10 48 89 f0 49 89 fe 48 89 e6 48 83 26 00 48 89 c7 e8"
            ]
        },
        "i2d_X509": {
            "signatures": [
                "55 41 56 53 48 83 ec 70 48 85 ff 0f 84 ?? ?? ?? ?? 48 89 f3 49 89 fe 48 8d 7c 24 40 6a 40",
                "48 8d 15 ?? ?? ?? ?? e9"
            ],
            "anchor": "bssl::x509_to_buffer"
        }
    },
    "android/x86": {
        "dart::bin::SSLCertContext::CertificateCallback": {
            "signatures": [
                "55 89 e5 53 57 56 83 e4 f0 83 ec 30 e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? bf 01 00 00 00 83 7d 08 01 0f 84"
            ]
        },
        "X509_STORE_CTX_get_current_cert": {
            "signatures": [
                "55 89 e5 83 e4 fc 8b 45 08 8b 40 2c 89 ec 5d c3",
                "55 89 e5 83 e4 fc 8b 45 08 8b 40 34 89 ec 5d c3",
                "55 89 e5 83 e4 fc 8b 45 08 8b 40 5c 89 ec 5d c3",
                "55 89 e5 83 e4 fc 8b 45 08 8b 40 64 89 ec 5d c3"
            ],
            "anchor": "dart::bin::SSLCertContext::CertificateCallback"
        },
        "bssl::x509_to_buffer": {
            "signatures": [
                "55 89 e5 53 57 56 83 e4 f0 83 ec 10 89 ce e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 8d 44 24 08 83 20 00 83 ec 08 50 52",
                "55 89 e5 53 56 83 e4 f0 83 ec 10 89 ce e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 8d 44 24 0c 83 20 00 83 ec 08 50 52",
                "55 89 e5 53 57 56 83 e4 f0 83 ec 20 89 ce e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 8d 44 24 14 83 20 00 89 44 24 04 89 14 24"
            ]
        },
        "i2d_X509": {
            "signatures": [
                "55 89 e5 53 57 56 83 e4 f0 83 ec 40 e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 8b 7d 08 85 ff 0f 84 ?? ?? ?? ?? 83 ec 08",
                "55 89 e5 53 83 e4 f0 83 ec 10 e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 83 ec 04 8d 83 ?? ?? ?? ?? 50 ff 75 0c ff 75 08"
            ],
            "anchor": "bssl::x509_to_buffer"
        }
    },

    "android/arm64": {
        "dart::bin::SSLCertContext::CertificateCallback": {
            "signatures": [
                "ff c3 00 d1 fe 57 01 a9 f4 4f 02 a9 1f 04 00 71 c0 07 00 54 f3 03 01 aa ?? ?? ?? 94",
                "ff c3 00 d1 fe 57 01 a9 f4 4f 02 a9 1f 04 00 71 c0 02 00 54 f3 03 01 aa ?? ?? ?? 94"
            ]
        },
        "X509_STORE_CTX_get_current_cert": {
            "signatures": [
                "00 ?? ?? f9 c0 03 5f d6"
            ],
            "anchor": "dart::bin::SSLCertContext::CertificateCallback"
        },
        "bssl::x509_to_buffer": {
            "signatures": [
                "fe 0f 1e f8 f4 4f 01 a9 e1 ?? ?? 91 f3 03 08 aa ff 07 00 f9 ?? ?? ?? 97 1f 04 00 71",
                "fe 0f 1e f8 f4 4f 01 a9 e8 03 01 aa f3 03 00 aa e1 ?? ?? 91 e0 03 08 aa ff 07 00 f9",
                "ff 83 00 d1 fe 4f 01 a9 e1 ?? ?? 91 f3 03 08 aa ff 07 00 f9 ?? ?? ?? 97 1f 00 00 71",
                "ff c3 00 d1 fe 7f 01 a9 f4 4f 02 a9 e1 ?? ?? 91 f3 03 08 aa ?? ?? ?? 97 1f 00 00 71",
                "ff c3 00 d1 fe 7f 01 a9 f4 4f 02 a9 e1 ?? ?? 91 f3 03 08 aa ?? ?? ?? 97 1f 04 00 71"
            ]
        },
        "i2d_X509": {
            "signatures": [
                "ff 43 02 d1 fe 57 07 a9 f4 4f 08 a9 a0 06 00 b4 f4 03 00 aa f3 03 01 aa e0 ?? ?? 91",
                "?2 ?? ?? ?? 42 ?? ?? 91 ?? ?? ?? 17"
            ],
            "anchor": "bssl::x509_to_buffer"
        }
    },
    "android/arm": {
        "dart::bin::SSLCertContext::CertificateCallback": {
            "signatures": [
                "70 b5 84 b0 01 28 02 d1 01 20 04 b0 70 bd 0c 46 ?? f? ?? f? 00 28 4d d0 20 46 ?? f? ?? f? 05 46 ?? f? ?? f",
                "70 b5 84 b0 01 28 02 d1 01 20 04 b0 70 bd 0c 46 ?? f? ?? f? 00 28 52 d0 20 46 ?? f? ?? f? 06 46 ?? f? ?? f",
                "70 b5 84 b0 01 28 02 d1 01 20 04 b0 70 bd 0c 46 ?? f? ?? f? 00 28 50 d0 20 46 ?? f? ?? f? 06 46 ?? f? ?? f"
            ]
        },
        "X509_STORE_CTX_get_current_cert": {
            "signatures": [
                "c0 6a 70 47",
                "40 6b 70 47",
                "c0 6d 70 47",
                "40 6e 70 47"
            ],
            "anchor": "dart::bin::SSLCertContext::CertificateCallback"
        },
        "bssl::x509_to_buffer": {
            "signatures": [
                "bc b5 00 25 0a 46 01 95 01 a9 04 46 10 46 ?? f? ?? f? 01 28 08 db 01 46 01 98 00 22 ?? f? ?? f? 05 46 01 98",
                "bc b5 00 25 0a 46 01 95 01 a9 04 46 10 46 ?? f? ?? f? 00 28 09 dd 01 46 01 98 00 22 ?? f? ?? f? 20 60 01 98",
                "7c b5 00 26 0a 46 01 96 01 a9 04 46 10 46 ?? f? ?? f? 00 28 0e dd 01 46 01 98 00 22 ?? f? ?? f? 05 46 01 98",
                "7c b5 00 26 0a 46 01 96 01 a9 04 46 10 46 ?? f? ?? f? 01 28 0d db 01 46 01 98 00 22 ?? f? ?? f? 05 46 01 98",
                "7c b5 00 26 0a 46 01 96 01 a9 04 46 10 46 ?? f? ?? f? 01 28 0e db 01 46 01 98 00 22 ?? f? ?? f? 05 46 00 90"
            ]
        },
        "i2d_X509": {
            "signatures": [
                "70 b5 8e b0 00 28 4f d0 05 46 08 a8 0c 46 40 21 ?? f? ?? f? 00 28 43 d0 2a 4a 08 a8 02 a9 ?? f? ?? f? e8 b3",
                "01 4a 7a 44 ?? f? ?? b"
            ],
            "anchor": "bssl::x509_to_buffer"
        }
    }
    }


    const MAX_ANCHOR_INSTRUCTIONS_TO_SCAN = 100;

    const CALL_MNEMONICS = ['call', 'bl', 'blx'];

    function scanForSignature(base, size, patterns) {
        const results = [];
        for (const pattern of patterns) {
            const result = Memory.scanSync(base, size, pattern);
            results.push(...result);
        }
        return results;
    }

    function scanForFunction(moduleRXRanges, platformPatterns, functionName, anchorFn) {
        const patternInfo = platformPatterns[functionName];
        const signatures = patternInfo.signatures;

        if (patternInfo.anchor) {
            const maxPatternByteLength = Math.max(...signatures.map(p => (p.length + 1) / 3));

            let addr = ptr(anchorFn);

            for (let i = 0; i < MAX_ANCHOR_INSTRUCTIONS_TO_SCAN; i++) {
                const instr = Instruction.parse(addr);
                addr = instr.next;
                if (CALL_MNEMONICS.includes(instr.mnemonic)) {
                    const callTargetAddr = ptr(instr.operands[0].value);
                    const results = scanForSignature(callTargetAddr, maxPatternByteLength, signatures);
                    if (results.length === 1) {
                        return results[0].address;
                    } else if (results.length > 1) {
                        console.log(`Found multiple matches for ${functionName} anchored by ${anchorFunction}:`, results);
                        throw new Error(`Found multiple matches for ${functionName}`);
                    }
                }
            }

            throw new Error(`Failed to find any match for ${functionName} anchored by ${anchorFn}`);
        } else {
            const results = moduleRXRanges.flatMap((range) => scanForSignature(range.base, range.size, signatures));
            if (results.length !== 1 && signatures.length > 1) {
                console.log(results);
                throw new Error(`Found multiple matches for ${functionName}`);
            }

            return results[0].address;
        }
    }

    function hookFlutter(moduleBase, moduleSize) {
        if (DEBUG_MODE) console.log('\n=== Disabling Flutter certificate pinning ===');

        const relevantRanges = Process.enumerateRanges('r-x').filter(range => {
            return range.base >= moduleBase && range.base < moduleBase.add(moduleSize);
        });

        try {
            const arch = Process.arch;
            const patterns = PATTERNS[`android/${arch}`];

            // This callback is called for all TLS connections. It immediately returns 1 (success) if BoringSSL
            // trusts the cert, or it calls the configured BadCertificateCallback if it doesn't. Note that this
            // is called for every cert in the chain individually - not the whole chain at once.
            const dartCertificateCallback = new NativeFunction(
                scanForFunction(relevantRanges, patterns, 'dart::bin::SSLCertContext::CertificateCallback'),
                'int',
                ['int', 'pointer']
            );

            // We inject code to check the certificate ourselves - getting the cert, converting to DER, and
            // ignoring all validation results if the certificate matches our trusted cert.
            const x509GetCurrentCert = new NativeFunction(
                scanForFunction(relevantRanges, patterns, 'X509_STORE_CTX_get_current_cert', dartCertificateCallback),
                'pointer',
                ['pointer']
            );

            // Just used as an anchor for searching:
            const x509ToBufferAddr = scanForFunction(relevantRanges, patterns, 'bssl::x509_to_buffer');
            const i2d_X509 = new NativeFunction(
                scanForFunction(relevantRanges, patterns, 'i2d_X509', x509ToBufferAddr),
                'int',
                ['pointer', 'pointer']
            );

            Interceptor.attach(dartCertificateCallback, {
                onEnter: function (args) {
                    this.x509Store = args[1];
                },
                onLeave: function (retval) {
                    if (retval.toInt32() === 1) return; // Ignore successful validations

                    // This certificate isn't trusted by BoringSSL or the app's certificate callback. Check it ourselves
                    // and override the result if it exactly matches our cert.
                    try {
                        const x509Cert = x509GetCurrentCert(this.x509Store);

                        const derLength = i2d_X509(x509Cert, NULL);
                        if (derLength <= 0) {
                            throw new Error('Failed to get DER length for X509 cert');
                        }

                        // We create our own target buffer (rather than letting BoringSSL do so, which would
                        // require more hooks to handle cleanup).
                        const derBuffer = Memory.alloc(derLength)
                        const outPtr = Memory.alloc(Process.pointerSize);
                        outPtr.writePointer(derBuffer);

                        const certDataLength = i2d_X509(x509Cert, outPtr)
                        const certData = new Uint8Array(derBuffer.readByteArray(certDataLength));

                        if (certData.every((byte, j) => CERT_DER[j] === byte)) {
                            retval.replace(1); // We trust this certificate, return success
                        }
                    } catch (error) {
                        console.error('[!] Internal error in Flutter certificate unpinning:', error);
                    }
                }
            });

            console.log('=== Flutter certificate pinning disabled ===');
        } catch (error) {
            console.error('[!] Error preparing Flutter certificate pinning hooks:', error);
            throw error;
        }
    }

    let flutter = Process.findModuleByName('libflutter.so');
    if (flutter) {
        hookFlutter(flutter.base, flutter.size);
    } else {
        waitForModule('libflutter.so', function (module) {
            hookFlutter(module.base, module.size);
        });
    }
})();
/** [MODULE 9] Anti-Detection & Stealth */
/**************************************************************************************************
 *
 * This script defines a large set of root detection bypasses for Android. Hooks included here
 * block detection of many known root indicators, including file paths, package names, commands,
 * notably binaries, and system properties.
 *
 * Enable DEBUG_MODE to see debug output for each bypassed check.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 * SPDX-FileCopyrightText: Riyad Mondal
 *
 *************************************************************************************************/

(() => {
    let loggedRootDetectionWarning = false;
    function logFirstRootDetection() {
        if (!loggedRootDetectionWarning) {
            console.log(" => Blocked possible root detection checks. Enable DEBUG_MODE for more details.");
            loggedRootDetectionWarning = true;
        }
    }

    const LIB_C = Process.findModuleByName("libc.so");

    const BUILD_FINGERPRINT_REGEX = /^([\w.-]+\/[\w.-]+\/[\w.-]+):([\w.]+\/[\w.-]+\/[\w.-]+):(\w+\/[\w,.-]+)$/;

    const CONFIG = {
        secureProps: {
            "ro.secure": "1",
            "ro.debuggable": "0",
            "ro.build.type": "user",
            "ro.build.tags": "release-keys"
        }
    };

    const ROOT_INDICATORS = {
        paths: new Set([
            "/data/local/bin/su",
            "/data/local/su",
            "/data/local/xbin/su",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/sbin/su",
            "/su/bin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/system/sbin/su",
            "/vendor/bin/su",
            "/data/adb/su/bin/su",
            "/system/bin/failsafe/su",
            "/system/bin/.ext/.su",
            "/system/bin/.ext/su",
            "/system/bin/failsafe/su",
            "/system/sd/xbin/su",
            "/system/usr/we-need-root/su",
            "/cache/su",
            "/data/su",
            "/dev/su",
            "/data/adb/magisk",
            "/sbin/.magisk",
            "/cache/.disable_magisk",
            "/dev/.magisk.unblock",
            "/cache/magisk.log",
            "/data/adb/magisk.img",
            "/data/adb/magisk.db",
            "/data/adb/magisk_simple",
            "/init.magisk.rc",
            "/system/app/Superuser.apk",
            "/system/etc/init.d/99SuperSUDaemon",
            "/system/xbin/daemonsu",
            "/system/xbin/ku.sud",
            "/data/adb/ksu",
            "/data/adb/ksud",
            "/system/xbin/busybox",
            "/system/app/Kinguser.apk"
        ]),

        packages: new Set([
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher",
            "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine",
            "com.ramdroid.appquarantinepro",
            "com.topjohnwu.magisk",
            "me.weishu.kernelsu"
        ]),

        commands: new Set([
            "su",
            "which su",
            "whereis su",
            "locate su",
            "find / -name su",
            "mount",
            "magisk",
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/su/bin/su"
        ]),

        binaries: new Set([
            "su",
            "busybox",
            "magisk",
            "supersu",
            "ksud",
            "daemonsu"
        ])
    };

    function bypassNativeFileCheck() {
        const fopen = LIB_C.findExportByName("fopen");
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave(retval) {
                    if (retval.toInt32() !== 0) {
                        const path = this.path.toLowerCase();
                        if (ROOT_INDICATORS.paths.has(this.path) || path.includes("magisk") || path.includes("/su") || path.endsWith("/su")) {
                            if (DEBUG_MODE) {
                                console.log(`Blocked possible root-detection: fopen ${this.path}`);
                            } else logFirstRootDetection();
                            retval.replace(ptr(0x0));
                        }
                    }
                }
            });
        }

        const access = LIB_C.findExportByName("access");
        if (access) {
            Interceptor.attach(access, {
                onEnter(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave(retval) {
                    if (retval.toInt32() === 0) {
                        const path = this.path.toLowerCase();
                        if (ROOT_INDICATORS.paths.has(this.path) || path.includes("magisk") || path.includes("/su") || path.endsWith("/su")) {
                            if (DEBUG_MODE) {
                                console.debug(`Blocked possible root detection: access ${this.path}`);
                            } else logFirstRootDetection();
                            retval.replace(ptr(-1));
                        }
                    }
                }
            });
        }

        const stat = LIB_C.findExportByName("stat");
        if (stat) {
            Interceptor.attach(stat, {
                onEnter(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave(retval) {
                    const path = this.path.toLowerCase();
                    if (ROOT_INDICATORS.paths.has(this.path) || path.includes("magisk") || path.includes("/su") || path.endsWith("/su")) {
                        if (DEBUG_MODE) {
                            console.debug(`Blocked possible root detection: stat ${this.path}`);
                        } else logFirstRootDetection();
                        retval.replace(ptr(-1));
                    }
                }
            });
        }

        const lstat = LIB_C.findExportByName("lstat");
        if (lstat) {
            Interceptor.attach(lstat, {
                onEnter(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave(retval) {
                    const path = this.path.toLowerCase();
                    if (ROOT_INDICATORS.paths.has(this.path) || path.includes("magisk") || path.includes("/su") || path.endsWith("/su")) {
                        if (DEBUG_MODE) {
                            console.debug(`Blocked possible root detection: lstat ${this.path}`);
                        } else logFirstRootDetection();
                        retval.replace(ptr(-1));
                    }
                }
            });
        }
    }

    function bypassJavaFileCheck() {
        function isRootIndicatorFile(file) {
            const path = file.getAbsolutePath();
            const filename = file.getName();
            return ROOT_INDICATORS.paths.has(path) ||
                path.includes("magisk") ||
                filename === "su";
        }

        const UnixFileSystem = Java.use("java.io.UnixFileSystem");
        UnixFileSystem.checkAccess.implementation = function(file, access) {
            if (isRootIndicatorFile(file)) {
                if (DEBUG_MODE) {
                    console.debug(`Blocked possible root detection: filesystem access check for ${file.getAbsolutePath()}`);
                } else logFirstRootDetection();
                return false;
            }
            return this.checkAccess(file, access);
        };

        const File = Java.use("java.io.File");
        File.exists.implementation = function() {
            if (isRootIndicatorFile(this)) {
                if (DEBUG_MODE) {
                    console.debug(`Blocked possible root detection: file exists check for ${this.getAbsolutePath()}`);
                } else logFirstRootDetection();
                return false;
            }
            return this.exists();
        };

        File.length.implementation = function() {
            if (isRootIndicatorFile(this)) {
                if (DEBUG_MODE) {
                    console.debug(`Blocked possible root detection: file length check for ${this.getAbsolutePath()}`);
                } else logFirstRootDetection();
                return 0;
            }
            return this.length();
        };

        const FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload('java.io.File').implementation = function(file) {
            if (isRootIndicatorFile(file)) {
                if (DEBUG_MODE) {
                    console.debug(`Blocked possible root detection: file stream for ${file.getAbsolutePath()}`);
                } else logFirstRootDetection();
                throw Java.use("java.io.FileNotFoundException").$new(file.getAbsolutePath());
            }
            return this.$init(file);
        };
    }

    function setProp() {
        const Build = Java.use("android.os.Build");

        // We do a little work to make the minimum changes required to hide in the BUILD fingerprint,
        // but otherwise keep matching the real device wherever possible.
        const realFingerprint = Build.FINGERPRINT.value;

        const fingerprintMatch = BUILD_FINGERPRINT_REGEX.exec(realFingerprint);
        let fixedFingerprint;
        if (fingerprintMatch) {
            let [, device, versions, tags] = BUILD_FINGERPRINT_REGEX.exec(realFingerprint);
            tags = 'user/release-keys'; // Should always be the case in production builds
            if (device.includes('generic') || device.includes('sdk') || device.includes('lineage')) {
                device = 'google/raven/raven';
            }

            fixedFingerprint = `${device}:${versions}:${tags}`;
        } else {
            console.warn(`Unexpected BUILD fingerprint format: ${realFingerprint}`);
            // This should never happen in theory (the format is standard), but just in case,
            // we use this fallback fingerprint:
            fixedFingerprint = "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys";
        }

        const fields = {
            "TAGS": "release-keys",
            "TYPE": "user",
            "FINGERPRINT": fixedFingerprint
        };

        Object.entries(fields).forEach(([field, value]) => {
            const fieldObj = Build.class.getDeclaredField(field);
            fieldObj.setAccessible(true);
            fieldObj.set(null, value);
        });

        const system_property_get = LIB_C.findExportByName("__system_property_get");
        if (system_property_get) {
            Interceptor.attach(system_property_get, {
                onEnter(args) {
                    this.key = args[0].readCString();
                    this.ret = args[1];
                },
                onLeave(retval) {
                    const secureValue = CONFIG.secureProps[this.key];
                    if (secureValue !== undefined) {
                        if (DEBUG_MODE) {
                            console.debug(`Blocked possible root detection: system_property_get ${this.key}`);
                        } else logFirstRootDetection();
                        const valuePtr = Memory.allocUtf8String(secureValue);
                        Memory.copy(this.ret, valuePtr, secureValue.length + 1);
                    }
                }
            });
        }

        const Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            if (cmd.startsWith("getprop ")) {
                const prop = cmd.split(" ")[1];
                if (CONFIG.secureProps[prop]) {
                    if (DEBUG_MODE) {
                        console.debug(`Blocked possible root detection: getprop ${prop}`);
                    } else logFirstRootDetection();
                    return null;
                }
            }
            return this.exec(cmd);
        };
    }

    function bypassRootPackageCheck() {
        const ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager");

        ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(str, i) {
            if (ROOT_INDICATORS.packages.has(str)) {
                if (DEBUG_MODE) {
                    console.debug(`Blocked possible root detection: package info for ${str}`);
                } else logFirstRootDetection();
                str = "invalid.example.nonexistent.package";
            }
            return this.getPackageInfo(str, i);
        };

        ApplicationPackageManager.getInstalledPackages.overload('int').implementation = function(flags) {
            const packages = this.getInstalledPackages(flags);
            const packageList = packages.toArray();
            const filteredPackages = packageList.filter(pkg => !ROOT_INDICATORS.packages.has(pkg.packageName?.value));
            return Java.use("java.util.ArrayList").$new(Java.use("java.util.Arrays").asList(filteredPackages));
        };
    }

    function bypassShellCommands() {
        const ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.command.overload('java.util.List').implementation = function(commands) {
            const cmdArray = commands.toArray();
            if (cmdArray.length > 0) {
                const cmd = cmdArray[0].toString();
                if (ROOT_INDICATORS.commands.has(cmd) || (cmdArray.length > 1 && ROOT_INDICATORS.binaries.has(cmdArray[1].toString()))) {
                    if (DEBUG_MODE) {
                        console.debug(`Blocked possible root detection: ProcessBuilder with ${cmdArray.join(' ')}`);
                    } else logFirstRootDetection();
                    return this.command(Java.use("java.util.Arrays").asList([""]));
                }
            }
            return this.command(commands);
        };

        const Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {
            if (cmdArray.length > 0) {
                const cmd = cmdArray[0];
                if (ROOT_INDICATORS.commands.has(cmd) || (cmdArray.length > 1 && ROOT_INDICATORS.binaries.has(cmdArray[1]))) {
                    if (DEBUG_MODE) {
                        console.debug(`Blocked possible root detection: Runtime.exec for ${cmdArray.join(' ')}`);
                    } else logFirstRootDetection();
                    return this.exec([""]);
                }
            }
            return this.exec(cmdArray);
        };

        const ProcessImpl = Java.use("java.lang.ProcessImpl");
        ProcessImpl.start.implementation = function(cmdArray, env, dir, redirects, redirectErrorStream) {
            if (cmdArray.length > 0) {
                const cmd = cmdArray[0].toString();
                const arg = cmdArray.length > 1 ? cmdArray[1].toString() : "";

                if (ROOT_INDICATORS.commands.has(cmd) || ROOT_INDICATORS.binaries.has(arg)) {
                    if (DEBUG_MODE) {
                        console.debug(`Blocked possible root detection: ProcessImpl.start for ${cmdArray.join(' ')}`);
                    } else logFirstRootDetection();
                    return ProcessImpl.start.call(this, [Java.use("java.lang.String").$new("")], env, dir, redirects, redirectErrorStream);
                }
            }
            return ProcessImpl.start.call(this, cmdArray, env, dir, redirects, redirectErrorStream);
        };
    }

    try {
        bypassNativeFileCheck();
        bypassJavaFileCheck();
        setProp();
        bypassRootPackageCheck();
        bypassShellCommands();
        console.log("== Disabled Android root detection ==");
    } catch (error) {
        console.error("\n !!! Error setting up root detection bypass !!!", error);
    }
})();

// --- END OF ENGINE ---
