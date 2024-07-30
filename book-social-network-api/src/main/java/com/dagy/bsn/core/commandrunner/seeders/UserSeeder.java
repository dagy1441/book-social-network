package com.dagy.bsn.core.commandrunner.seeders;

import com.dagy.bsn.features.role.RoleRepository;
import com.dagy.bsn.features.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

//@Component
@RequiredArgsConstructor
public class UserSeeder {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;

    public void run() {
        this.seedUser();
    }


    private void seedUser() {}
}
