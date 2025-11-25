package com.pnm.auth.exception;

public class EmailSendFailedException extends RuntimeException{
    public EmailSendFailedException(String message){
        super(message);
    }
}
