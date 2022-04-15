package com.meteoauth.MeteoAuth.controller;

import com.meteoauth.MeteoAuth.assembler.MeasuredValuesAssembler;
import com.meteoauth.MeteoAuth.dto.MeasuredValuesDtoRequest;
import com.meteoauth.MeteoAuth.dto.MeasuredValuesDtoResponse;
import com.meteoauth.MeteoAuth.entities.MeasuredValue;
import com.meteoauth.MeteoAuth.entities.Station;
import com.meteoauth.MeteoAuth.repository.MeasuredValuesRepository;
import com.meteoauth.MeteoAuth.repository.StationsRepository;
import com.meteoauth.MeteoAuth.services.TokenProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/measured_values")
public class MeasuredValuesController {
    private final MeasuredValuesRepository measuredValuesRepository;
    private final MeasuredValuesAssembler measuredValuesAssembler;
    private final TokenProvider tokenProvider;
    private final StationsRepository stationsRepository;

    public MeasuredValuesController(MeasuredValuesRepository measuredValuesRepository, MeasuredValuesAssembler measuredValuesAssembler, TokenProvider tokenProvider, StationsRepository stationsRepository) {
        this.measuredValuesRepository = measuredValuesRepository;
        this.measuredValuesAssembler = measuredValuesAssembler;
        this.tokenProvider = tokenProvider;
        this.stationsRepository = stationsRepository;
    }

    @PostMapping("/create")
    public ResponseEntity<MeasuredValuesDtoResponse> createMeasuredValues(@RequestBody @Valid MeasuredValuesDtoRequest measuredValuesDtoRequest,
                                                                          @RequestHeader(name = "Authorization") String token) {
        Long id = Long.parseLong(tokenProvider.extractSubject(token));

        MeasuredValue measuredValue = measuredValuesAssembler.createMeasuredValues(measuredValuesDtoRequest, id);
        measuredValue = measuredValuesRepository.save(measuredValue);
        return ResponseEntity.ok().body(measuredValuesAssembler.getMeasuredValuesDtoResponse(measuredValue));

    }

    @GetMapping("/all")
    public ResponseEntity<List<MeasuredValuesDtoResponse>> getMeasuredValues() {
        Iterable<MeasuredValue> measuredValuesList = measuredValuesRepository.findAll();
        return ResponseEntity.ok().body(measuredValuesAssembler.getMeasuredValuesDtoRequestList(measuredValuesList));
    }

    @GetMapping("/by-station")
    public ResponseEntity<List<MeasuredValuesDtoResponse>> getMeasuredValuesByStation(@RequestHeader(name = "Authorization") String token) {
        Long id = Long.parseLong(tokenProvider.extractSubject(token));
        Optional<Station> station = stationsRepository.findById(id);
        if (station.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        Iterable<MeasuredValue> measuredValuesList = measuredValuesRepository.findByStation(station.get());
        return ResponseEntity.ok().body(measuredValuesAssembler.getMeasuredValuesDtoRequestList(measuredValuesList));
    }

    @GetMapping("/by-station/{id}")
    public ResponseEntity<List<MeasuredValuesDtoResponse>> getMeasuredValuesByStation(@PathVariable("id") Long stationID) {
        Optional<Station> station = stationsRepository.findById(stationID);
        if (station.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        Iterable<MeasuredValue> measuredValuesList = measuredValuesRepository.findByStation(station.get());
        return ResponseEntity.ok().body(measuredValuesAssembler.getMeasuredValuesDtoRequestList(measuredValuesList));
    }

    @DeleteMapping("{id}")
    public ResponseEntity<Void> deleteOwnerMeasuredValues(@PathVariable("id") Long measuredValueID, @RequestHeader(name = "Authorization") String token) {
        Optional<MeasuredValue> optionalMeasuredValue = measuredValuesRepository.findById(measuredValueID);
        if (optionalMeasuredValue.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        MeasuredValue measuredValue = optionalMeasuredValue.get();
        Long id = Long.parseLong(tokenProvider.extractSubject(token));
        Optional<Station> station = stationsRepository.findById(id);
        if (station.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        if (!measuredValue.getStation().equals(station.get())) {
            return ResponseEntity.badRequest().build();
        }
        optionalMeasuredValue.ifPresent(measuredValuesRepository::delete);
        return ResponseEntity.ok().build();
    }
}