package com.example.airlist.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Airport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "a_id")
    private Long id;

    @Column(name = "a_NameK")
    private String aNameKor; //김포
    @Column(name = "a_NameE")
    private String aNameEng;  //Gimpo
    @Column(name = "a_Code")
    private String aCode; //GMP
    @Column(name = "a_City")
    private String aCity; //서울
}
