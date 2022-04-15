package com.meteoauth.MeteoAuth.entities;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.sql.Timestamp;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "tb_measured_value")
public class MeasuredValue {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY, generator = "native")
    @Column
    private Long id;

    @Basic
    @Column
    private Timestamp measurementTime = new Timestamp(System.currentTimeMillis());

    @Basic
    @Column
    private Integer humidity;

    @Basic
    @Column
    private Integer temperature;

    @Basic
    @Column
    private Integer air_quality;

    @Basic
    @Column
    private Integer wind_speed;

    @Basic
    @Column
    private Integer wind_gusts;

    @Basic
    @Column
    private Integer wind_direction;

    @Basic
    @Column
    private Integer rainfall;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "station_id", nullable = false)
    private Station station;
}
