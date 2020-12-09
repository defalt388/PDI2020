package com.PSN.crudPDI

import com.PSN.crudPDI.model.PSN4
import com.PSN.crudPDI.repository.PSRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Component

@Component
class PlayerDetailService: UserDetailsService {

    @Autowired
    private lateinit var repository: PSRepository

    @Throws(UsernameNotFoundException::class)
    override fun loadUserByUsername(username: String): UserDetails? {
        val player: PSN4 = repository.findPlayerByNome(username)
        return if (player == null) {
            throw UsernameNotFoundException("No user found with username: $username")
        } else {
            User.builder() //Юзер имплементит детали так что все в порядке
                    .accountExpired(false)
                    .accountLocked(false)
                    .credentialsExpired(false)
                    .username(player.nome) //логин
                    .password(player.idtag) //пароль
                    .authorities("USER") //полномочия, берем из ролей
                    .build()
        }
    }

//    private fun getAuthorities(account: PSN4): Set<GrantedAuthority>? {
//        val authorities: MutableSet<GrantedAuthority> = HashSet()
//        for (role in account.getRoles()) {
//            authorities.add(SimpleGrantedAuthority(role.getRole()))
//        }
//        return authorities
//    }
}