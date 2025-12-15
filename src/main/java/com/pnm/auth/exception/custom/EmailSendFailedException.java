package com.pnm.auth.exception.custom;

public class EmailSendFailedException extends RuntimeException{
    public EmailSendFailedException(String message){
        super(message);
    }
}
