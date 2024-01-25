package com.aliens.IdentityManagement.entity;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

@Data
@NoArgsConstructor
public class ResponseBody {

    HttpStatus status;
    String body;

    public HttpStatus getStatus() {
        return status;
    }

    public void setStatus(HttpStatus status) {
        this.status = status;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public ResponseBody(HttpStatus status, String body) {
        this.status = status;
        this.body = body;
    }
}

