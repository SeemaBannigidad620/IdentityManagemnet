package com.aliens.IdentityManagement.utils;

import com.aliens.IdentityManagement.entity.User;
import com.aliens.IdentityManagement.exception.InvalidUserDataException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

@Component
public class ValidationUtils {
    public void validateUserDetails(User user) {

        if (ObjectUtils.isEmpty(user.getUserName()) || ObjectUtils.isEmpty(user.getEmail())) {
            throw new InvalidUserDataException(HttpStatus.BAD_REQUEST, "UserName or email cannot be empty");
        }

        if (isValidEmail(user.getEmail())) {
            throw new InvalidUserDataException(HttpStatus.BAD_REQUEST, "Invalid email address");
        }

        if (user.getPhone_number() <= 0 || !isValidPhoneNumber(user.getPhone_number())) {
            throw new InvalidUserDataException(HttpStatus.BAD_REQUEST, "Invalid phone number");
        }

        if (ObjectUtils.isEmpty(user.getPassword()) || user.getPassword().length() < 8 ||
                isValidEmail(user.getEmail())) {
            throw new InvalidUserDataException(HttpStatus.BAD_REQUEST, "Password must be at least 8 characters long");
        }
    }

    private boolean isValidEmail(String email) {
        return !email.matches(".*[a-z].*\\..*[0-9].*@.*");
    }

    private boolean isValidPhoneNumber(long phoneNumber) {
        String phoneNumberString = String.valueOf(phoneNumber);
        return !phoneNumberString.isEmpty() && phoneNumberString.length() <= 10;
    }

    private boolean isValidPassword(String password) {
        return password.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@]).+$");
    }
}
