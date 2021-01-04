package com.wang.learnJava8;

import org.springframework.core.convert.converter.Converter;

import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * @Description: TODO
 * @Auther: shanpeng.wang
 * @Create: 2021/1/4 09:55
 */
public class Java8Collection {

    public static void main(String[] args) {
        //1集合排序
        List<String> names = Arrays.asList("peter", "anna", "mike", "xenia");
//        Collections.sort(names, new Comparator<String>() {
//            @Override
//            public int compare(String a, String b) {
//                return b.compareTo(a);
//            }
//        });
        //java8
//        Collections.sort(names, (String a, String b) -> b.compareTo(a));

        names.sort((a, b) -> b.compareTo(a));
        names.forEach(s -> {
            System.out.println(s);
        });


        //2.集合遍历 流操作
        List<String> stringCollection = Arrays.asList("peter", "anna", "mike", "xenia");
        stringCollection
                .stream()
                .sorted((a, b) -> b.compareTo(a))//排序
                .filter((s) -> s.startsWith("a"))//过滤
                .forEach(System.out::println);//遍历输出
                //.allMatch((s) -> s.startsWith("a"));  验证 list 中 string 是否都是以 a 开头的
                //.noneMatch((s) -> s.startsWith("z"));验证 list 中 string 是否都不是以 z 开头的
                //.anyMatch((s) -> s.startsWith("a")); 验证 list 中 string 是否有以 a 开头的, 匹配到第一个，即返回 true
                // .count();计数
                // .map(String::toUpperCase) 转换成大写
                //.collect(Collectors.toList()); // 生成一个新的 List


        Arrays.stream(new int[] {1, 2, 3})
                .map(n -> 2 * n + 1) // 对数值中的每个对象执行 2*n + 1 操作
                .average() // 求平均值
                .ifPresent(System.out::println);  // 如果值不为空，则输出


    }


}
