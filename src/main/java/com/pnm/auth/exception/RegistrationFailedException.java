package com.pnm.auth.exception;

public class RegistrationFailedException extends RuntimeException {
  public RegistrationFailedException(String message) {
    super(message);
  }
}
