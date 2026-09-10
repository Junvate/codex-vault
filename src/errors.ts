export class VaultError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "VaultError";
  }
}

export class AuthenticationError extends VaultError {
  constructor(message = "Authentication failed", options?: ErrorOptions) {
    super(message, options);
    this.name = "AuthenticationError";
  }
}

export class IntegrityError extends VaultError {
  constructor(message = "Vault integrity verification failed", options?: ErrorOptions) {
    super(message, options);
    this.name = "IntegrityError";
  }
}
