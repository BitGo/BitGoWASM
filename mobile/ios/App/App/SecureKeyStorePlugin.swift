import Capacitor
import Security
import LocalAuthentication

@objc(SecureKeyStorePlugin)
public class SecureKeyStorePlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "SecureKeyStorePlugin"
    public let jsName = "SecureKeyStore"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "store", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "retrieve", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "remove", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "has", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "isBiometricAvailable", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "generateEntropy", returnType: CAPPluginReturnPromise),
    ]

    private let serviceName = "com.bitgo.psbtsigner"

    // MARK: - store

    @objc func store(_ call: CAPPluginCall) {
        guard let key = call.getString("key"),
              let value = call.getString("value") else {
            call.reject("Missing required parameters: key and value")
            return
        }

        guard let valueData = value.data(using: .utf8) else {
            call.reject("Failed to encode value")
            return
        }

        // Create access control: biometric first, device passcode as fallback
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .userPresence,
            &error
        ) else {
            call.reject("Failed to create access control: \(error?.takeRetainedValue().localizedDescription ?? "unknown")")
            return
        }

        // Delete any existing item first (Keychain doesn't support upsert)
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        // Add the new item with biometric access control
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecValueData as String: valueData,
            kSecAttrAccessControl as String: accessControl,
        ]

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        if status == errSecSuccess {
            call.resolve()
        } else {
            call.reject("Failed to store key: \(SecCopyErrorMessageString(status, nil) ?? "unknown" as CFString)")
        }
    }

    // MARK: - retrieve

    @objc func retrieve(_ call: CAPPluginCall) {
        guard let key = call.getString("key") else {
            call.reject("Missing required parameter: key")
            return
        }

        let prompt = call.getString("prompt") ?? "Authenticate to access key"

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecUseOperationPrompt as String: prompt,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data,
                  let value = String(data: data, encoding: .utf8) else {
                call.reject("Failed to decode stored value")
                return
            }
            call.resolve(["value": value])

        case errSecUserCanceled:
            call.reject("Authentication cancelled", "USER_CANCELLED")

        case errSecAuthFailed:
            call.reject("Authentication failed", "AUTH_FAILED")

        case errSecItemNotFound:
            call.reject("No key stored", "NOT_FOUND")

        case errSecInteractionNotAllowed:
            call.reject("Device locked", "INTERACTION_NOT_ALLOWED")

        default:
            call.reject("Keychain error: \(SecCopyErrorMessageString(status, nil) ?? "unknown" as CFString)")
        }
    }

    // MARK: - remove

    @objc func remove(_ call: CAPPluginCall) {
        guard let key = call.getString("key") else {
            call.reject("Missing required parameter: key")
            return
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
        ]

        let status = SecItemDelete(query as CFDictionary)
        if status == errSecSuccess || status == errSecItemNotFound {
            call.resolve()
        } else {
            call.reject("Failed to remove key: \(SecCopyErrorMessageString(status, nil) ?? "unknown" as CFString)")
        }
    }

    // MARK: - has

    @objc func has(_ call: CAPPluginCall) {
        guard let key = call.getString("key") else {
            call.reject("Missing required parameter: key")
            return
        }

        // Query attributes only, suppress biometric prompt
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecReturnAttributes as String: true,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
        ]

        let status = SecItemCopyMatching(query as CFDictionary, nil)

        switch status {
        case errSecSuccess, errSecInteractionNotAllowed:
            // errSecInteractionNotAllowed means item exists but is biometric-protected
            call.resolve(["exists": true])
        case errSecItemNotFound:
            call.resolve(["exists": false])
        default:
            call.resolve(["exists": false])
        }
    }

    // MARK: - generateEntropy

    @objc func generateEntropy(_ call: CAPPluginCall) {
        let bytes = call.getInt("bytes") ?? 32

        guard bytes >= 16 && bytes <= 64 else {
            call.reject("Byte count must be between 16 and 64")
            return
        }

        var randomBytes = [UInt8](repeating: 0, count: bytes)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes, &randomBytes)

        guard status == errSecSuccess else {
            call.reject("Failed to generate random bytes: \(status)")
            return
        }

        let hex = randomBytes.map { String(format: "%02x", $0) }.joined()
        call.resolve(["entropy": hex])
    }

    // MARK: - isBiometricAvailable

    @objc func isBiometricAvailable(_ call: CAPPluginCall) {
        let context = LAContext()
        var error: NSError?
        let available = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)

        var biometryType = "none"
        if available {
            switch context.biometryType {
            case .faceID:
                biometryType = "faceId"
            case .touchID:
                biometryType = "touchId"
            case .opticID:
                biometryType = "opticId"
            @unknown default:
                biometryType = "unknown"
            }
        }

        call.resolve([
            "available": available,
            "biometryType": biometryType,
        ])
    }
}
