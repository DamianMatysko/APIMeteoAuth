package com.meteoauth.MeteoAuth.entities;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.sql.Timestamp;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "tb_station")
public class Station {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY, generator = "native")
    @Column
    private Long id;

    @Basic
    @Column(unique = true)
    private String title;

    @Basic
    @Column
    private String destination;

    @Basic
    @Column
    private String model_description;

    @Basic
    @Column
    private Timestamp registration_time = new Timestamp(System.currentTimeMillis());

    @Basic
    @Column
    private String phone;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @OneToMany(mappedBy = "station")
    private Set<MeasuredValue> measuredValues;
}
