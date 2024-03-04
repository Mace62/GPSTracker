import gpxpy
import gpxpy.gpx

def gpx_parse(filename):
    with open(filename, 'r') as gpx_file:
        data = gpxpy.parse(gpx_file)
        gpxfile = GPXFile(filename)

    for waypoint in data.waypoints:
        gpxfile.waypoints.append(GPXPoint(waypoint.name, waypoint.latitude, waypoint.longitude, waypoint.elevation, waypoint.time, waypoint.description))

    for route in data.routes:
        route_name = route.name if route.name else "Unnamed Route"
        track = GPXTrack(route_name)
        for point in route.points:
            track.points.append(GPXPoint(point.name, point.latitude, point.longitude, point.elevation, point.time, point.description))

def gpx_display(name):
    name.display_info()