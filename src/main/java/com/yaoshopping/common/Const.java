package com.yaoshopping.common;

public class Const {
    public static final String CURRENT_USER = "currentUser";

    public static final String EMAIL = "email";
    public static final String USERNAME = "username";

    public interface Role{
        int ROLE_CUSTOMER = 0; // common users
        int ROLE_ADMIN = 1;// administrators
    }
}
