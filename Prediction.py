from datetime import datetime, date
from numpy.lib.function_base import average
import pandas as pd
import numpy as np
import ctypes
import time

# import requests module
import requests
  
# Making a get request
response = requests.get('http://staging.2excel.com.au:8586/api/trip/') #taking the json data from api

data = response.json() #storing in data variable 

df = pd.DataFrame(data)  #by using dataframe loading the json data
df.drop(labels=['connected'],axis=1,inplace=True)   #id and connected column is drop because it is not required 
# print(df)
# row = df.loc[:, "time"]
# print(row)

#converting all columns type from object to float for further operation
df['longitude_rx']=df['longitude_rx'].astype(str).astype(float)     
df['longitude_tx']=df['longitude_tx'].astype(str).astype(float)
df['latitude_rx']=df['latitude_rx'].astype(str).astype(float)
df['latitude_tx']=df['latitude_tx'].astype(str).astype(float)
df['distance']=df['distance'].astype(str).astype(float)
df['time'] = pd.to_datetime(df['time'])
df['time'] = pd.to_datetime(df['time'], format='%m/%d/%Y %H:%M')
print(df)

#Taking both longitude and latitude for finding distance 
lon1 = df.loc[:,"longitude_rx"]  
lon2 = df.loc[:,"longitude_tx"]
lat1 = df.loc[:,"latitude_rx"]
lat2 = df.loc[:,"latitude_tx"]

from math import sin, cos, sqrt, atan2, radians

def getDistanceFromLatLonInKm(lat1,lon1,lat2,lon2):
    R = 6371 # Radius of the earth in km
    dLat = radians(lat2-lat1)
    dLon = radians(lon2-lon1)
    rLat1 = radians(lat1)
    rLat2 = radians(lat2)
    a = sin(dLat/2) * sin(dLat/2) + cos(rLat1) * cos(rLat2) * sin(dLon/2) * sin(dLon/2) 
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    d = R * c # Distance in km
    return d

def calc_velocity(dist_km, time_start, time_end):
    """Return 0 if time_start == time_end, avoid dividing by 0"""
    return dist_km / (time_end - time_start).seconds if time_end > time_start else 0

df = df.sort_values(by=['id', 'time'])

# Group the sorted dataframe by ID, and grab the initial value for lat, lon, and time.
df['lat0'] = df.groupby('id')['latitude_rx'].transform(lambda x: x.iat[0])
df['lon0'] = df.groupby('id')['longitude_rx'].transform(lambda x: x.iat[0])
df['t0'] = df.groupby('id')['time'].transform(lambda x: x.iat[0])

df['dist_km'] = df.apply(
    lambda row: getDistanceFromLatLonInKm(
        lat1=row['latitude_rx'],
        lon1=row['longitude_rx'],
        lat2=row['lat0'],
        lon2=row['lon0']
    ),
    axis=1
)

# create a new column for velocity
df['velocity_kmps'] = df.apply(
    lambda row: calc_velocity(
        dist_km=row['dist_km'],
        time_start=row['t0'],
        time_end=row['time']
    ),
    axis=1
)
print(df[['id', 'time', 'latitude_rx', 'longitude_rx', 'dist_km', 'velocity_kmps']])
