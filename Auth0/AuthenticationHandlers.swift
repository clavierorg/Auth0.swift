import Foundation
import JWTDecode

func authenticationDecodable<T: Decodable>(
    from result: Result<ResponseValue, AuthenticationError>,
    callback: Request<T, AuthenticationError>.Callback
) {
    do {
        let response = try result.get()
        if let data = response.data {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .secondsSince1970
            let decodedObject = try decoder.decode(T.self, from: data)
            callback(.success(decodedObject))
        } else {
            callback(.failure(AuthenticationError(from: response)))
        }
    } catch let error as AuthenticationError {
        callback(.failure(error))
    } catch {
        callback(.failure(AuthenticationError(cause: error)))
    }
}

func authenticationObject<T: JSONObjectPayload>(
    from result: Result<ResponseValue, AuthenticationError>,
    callback: Request<T, AuthenticationError>.Callback
) {
    do {
        let response = try result.get()
        if let dictionary = json(response.data) as? [String: Any],
            let object = T(json: dictionary)
        {
            callback(.success(object))
        } else {
            callback(.failure(AuthenticationError(from: response)))
        }
    } catch {
        callback(.failure(error))
    }
}

func authenticationDatabaseUser(
    from result: Result<ResponseValue, AuthenticationError>,
    callback: Request<DatabaseUser, AuthenticationError>.Callback
) {
    do {
        let response = try result.get()
        if let dictionary = json(response.data) as? [String: Any],
            let email = dictionary["email"] as? String
        {
            let username = dictionary["username"] as? String
            let verified = dictionary["email_verified"] as? Bool ?? false
            callback(.success((email: email, username: username, verified: verified)))
        } else {
            callback(.failure(AuthenticationError(from: response)))
        }
    } catch {
        callback(.failure(error))
    }
}

func authenticationNoBody(
    from result: Result<ResponseValue, AuthenticationError>,
    callback: Request<Void, AuthenticationError>.Callback
) {
    do {
        _ = try result.get()
        callback(.success(()))
    } catch let error where error.code == emptyBodyError {
        callback(.success(()))
    } catch {
        callback(.failure(error))
    }
}

// MARK: - WorkOS Helpers

/// Decodes WorkOS credential responses, supporting both `expires_in` (seconds) and `expires_at` (unix epoch seconds).
/// Falls back to `Date()` if neither value is present.
func workOSCredentialsDecodable(
    from result: Result<ResponseValue, AuthenticationError>,
    callback: Request<Credentials, AuthenticationError>.Callback
) {
    do {
        let response = try result.get()
        guard let data = response.data else {
            return callback(.failure(AuthenticationError(from: response)))
        }

        // Decode as a loose dictionary to allow multiple shapes/types
        guard let dictionary = json(data) as? [String: Any] else {
            return callback(.failure(AuthenticationError(from: response)))
        }

        // Helpers to read numeric values that might be numbers or strings
        func number(from any: Any?) -> Double? {
            if let value = any as? Double { return value }
            if let value = any as? NSNumber { return value.doubleValue }
            if let value = any as? String, let parsed = Double(value) { return parsed }
            return nil
        }

        let accessToken = (dictionary["access_token"] as? String) ?? ""
        let tokenType = (dictionary["token_type"] as? String) ?? ""
        let idToken = (dictionary["id_token"] as? String) ?? ""
        let refreshToken = dictionary["refresh_token"] as? String
        let scope = dictionary["scope"] as? String

        var expiresAtDate: Date = Date()
        if let seconds = number(from: dictionary["expires_in"])
            ?? number(from: dictionary["expiresIn"])
        {
            expiresAtDate = Date(timeIntervalSinceNow: seconds)
        } else if let epoch = number(from: dictionary["expires_at"])
            ?? number(from: dictionary["expiresAt"])
        {
            let seconds = (epoch > 1_000_000_000_000) ? (epoch / 1000.0) : epoch
            expiresAtDate = Date(timeIntervalSince1970: seconds)
        } else if let s = (dictionary["expires_at"] as? String)
            ?? (dictionary["expiresAt"] as? String)
        {
            let iso = ISO8601DateFormatter()
            if let d = iso.date(from: s) {
                expiresAtDate = d
            } else {
                let fmt = DateFormatter()
                fmt.locale = Locale(identifier: "en_US_POSIX")
                fmt.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSXXXXX"
                if let d = fmt.date(from: s) {
                    expiresAtDate = d
                } else {
                    fmt.dateFormat = "yyyy-MM-dd'T'HH:mm:ssXXXXX"
                    if let d2 = fmt.date(from: s) {
                        expiresAtDate = d2
                    }
                }
            }
        }

        // Fallback: if we couldn't parse an explicit expiration, attempt to read `exp` from JWTs
        if expiresAtDate <= Date(), !accessToken.isEmpty || !idToken.isEmpty {
            func jwtExpiry(_ token: String) -> Date? {
                guard token.split(separator: ".").count == 3 else { return nil }
                if let jwt = try? decode(jwt: token), let exp = jwt.expiresAt { return exp }
                return nil
            }
            if let d = jwtExpiry(accessToken) ?? jwtExpiry(idToken) {
                expiresAtDate = d
            }
        }

        let credentials = Credentials(
            accessToken: accessToken,
            tokenType: tokenType,
            idToken: idToken,
            refreshToken: refreshToken,
            expiresIn: expiresAtDate,
            scope: scope)
        callback(.success(credentials))
    } catch let error as AuthenticationError {
        callback(.failure(error))
    } catch {
        callback(.failure(AuthenticationError(cause: error)))
    }
}
