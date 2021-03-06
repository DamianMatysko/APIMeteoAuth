package com.meteoauth.MeteoAuth.assembler;

import com.meteoauth.MeteoAuth.dto.StationDtoRequest;
import com.meteoauth.MeteoAuth.dto.StationsDtoResponse;
import com.meteoauth.MeteoAuth.entities.Station;
import com.meteoauth.MeteoAuth.repository.UserRepository;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class StationsAssembler {
    private final UserRepository userRepository;
    private final UserAssembler userAssembler;

    public StationsAssembler(UserRepository userRepository, UserAssembler userAssembler) {
        this.userRepository = userRepository;
        this.userAssembler = userAssembler;
    }

    public StationsDtoResponse getStationDtoResponse(Station station) {
        StationsDtoResponse stationsDtoResponse = new StationsDtoResponse();
        stationsDtoResponse.setId(station.getId());
        stationsDtoResponse.setDestination(station.getDestination());
        stationsDtoResponse.setModel_description(station.getModel_description());
        stationsDtoResponse.setPhone(station.getPhone());
        stationsDtoResponse.setRegistration_time(station.getRegistration_time());
        stationsDtoResponse.setTitle(station.getTitle());
        stationsDtoResponse.setUser(userAssembler.getUserDtoResponse(station.getUser()));
        return stationsDtoResponse;
    }

    public Station createStation(StationDtoRequest stationDtoRequest, String email) {
        Station station = new Station();
        station.setDestination(stationDtoRequest.getDestination());
        station.setModel_description(stationDtoRequest.getModel_description());
        station.setPhone(stationDtoRequest.getPhone());
        station.setTitle(stationDtoRequest.getTitle());
        station.setUser(userRepository.findByEmail(email));
        return station;
    }

    public List<StationsDtoResponse> getStationDtoRequestList(Iterable<Station> stationList) {
        List<StationsDtoResponse> stationsDtoResponses = new ArrayList<>();
        for (Station station : stationList) {
            StationsDtoResponse temp = new StationsDtoResponse();
            temp.setId(station.getId());
            temp.setDestination(station.getDestination());
            temp.setModel_description(station.getModel_description());
            temp.setPhone(station.getPhone());
            temp.setRegistration_time(station.getRegistration_time());
            temp.setTitle(station.getTitle());
            temp.setUser(userAssembler.getUserDtoResponse(station.getUser()));
            stationsDtoResponses.add(temp);
        }
        return stationsDtoResponses;
    }
}