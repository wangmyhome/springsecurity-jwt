package com.wang.security.repository;

import com.wang.security.bean.User;
import org.springframework.data.repository.CrudRepository;

/**
 * @Description: TODO
 * @Auther: shanpeng.wang
 * @Create: 2020/12/28 16:39
 */
public interface UserRepository extends CrudRepository<User, Integer> {
        User findByUsername(String username);
}
