package com.pnm.auth.exception.custom;

public class RegistrationFailedException extends RuntimeException {
  public RegistrationFailedException(String message) {
    super(message);
  }
}
