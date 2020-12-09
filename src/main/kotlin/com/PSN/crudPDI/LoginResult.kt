package com.PSN.crudPDI

import lombok.Data
import lombok.RequiredArgsConstructor

@Data
@RequiredArgsConstructor
class LoginResult(jwt: String) {
    private lateinit var jwt: String
}