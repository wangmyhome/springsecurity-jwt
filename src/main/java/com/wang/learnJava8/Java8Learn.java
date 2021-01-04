package com.wang.learnJava8;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * @Description:
 *  1.字符串判空
 *  2.集合遍历前判空
 *
 *
 * @Auther: shanpeng.wang
 * @Create: 2021/1/4 09:48
 */
public class Java8Learn {
    public static void main(String[] args) {

        //1
        String s = null;
        //Optional.ofNullable(变量).orElse(默认值)
        String s1 = Optional.ofNullable(s).orElse("");
        int length = s1.length();
        System.out.println(s);
        System.out.println(s1);
        System.out.println(length);

        //2
        List<String> list = new ArrayList<>();
        list.add("a");
        list.add("b");
        list.add("c");
        //集合判空遍历
        Optional.ofNullable(list).orElse(new ArrayList<>()).forEach(o -> {
            System.out.println(o);
        });
    }
}
