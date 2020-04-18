package com.thed.zephyr.cloud.rest.exception;

public class JobProgressException  extends Exception
{
    public JobProgressException() 
    {
    	
    }

    public JobProgressException(String message) 
    {
        super(message);
    }

    public JobProgressException(String message, Throwable cause) 
    {
        super(message, cause);
    }

    public JobProgressException(Throwable cause) 
    {
        super(cause);
    }

    public JobProgressException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) 
    {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
