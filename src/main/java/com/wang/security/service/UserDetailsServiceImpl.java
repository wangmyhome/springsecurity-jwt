package com.wang.security.service;

import com.wang.security.bean.JwtUser;
import com.wang.security.bean.User;
import com.wang.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * @Description: 实现UserDetailsService接口
 * @Auther: shanpeng.wang
 * @Create: 2020/12/28 16:40
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(s);
        return new JwtUser(user);
    }
}
