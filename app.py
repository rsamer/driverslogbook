from flask import Flask, g
from flask import request
from flask import jsonify
from flask import render_template
from flask_cors import CORS
from flask_admin import Admin
from flask_expects_json import expects_json
from bs4 import BeautifulSoup
from cachetools import TTLCache
from models.data_models import AdminUser
from authentication.auth_blueprint import auth_blueprint
from authentication import authentication_required
from models import data_models
from models.data_models import db
import numpy as np
import requests
import os


template_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'templates')
app = Flask(__name__, template_folder=template_dir)
app.name = "Logbook"
app_settings = os.getenv('APP_SETTINGS', 'config.DevelopmentConfig')
app.config.from_object(app_settings)
data_models.db.init_app(app)
data_models.bcrypt.init_app(app)
data_models.basic_auth.init_app(app)
PRICE_CACHE = TTLCache(maxsize=8388608, ttl=30)  # caching for 3 hours


def create_and_add_admin_users_to_database(config):
    for admin_info in config["API_ADMINS"]:
        if data_models.db.session.query(AdminUser).filter(AdminUser.email == admin_info["email"]).first() is None:
            data_models.db.session.add(AdminUser(**admin_info))
    data_models.db.session.commit()


@app.errorhandler(404)
def not_found_error(error):
    return render_template('error/404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error/500.html'), 500


@app.route('/driverslogbook/view', methods=['GET'])
def view_driverslogbook_list():
    with app.app_context():
        logbooks = db.session.query(data_models.Logbook).all()
        return render_template('logbook/list.html', logbooks=logbooks, googlemapskey=app.config['GOOGLE_MAPS_KEY'])


@app.route('/driverslogbook/<int:logbook_id>/view', methods=['GET'])
def view_driverslogbook(logbook_id=0):
    with app.app_context():
        logbook = db.session.query(data_models.Logbook).filter(data_models.Logbook.id == logbook_id).first()

        if logbook is None:
            return None, 404

        waypoints_idx = set(map(lambda n: int(n), np.linspace(1, len(logbook.location_samples) - 2, num=5))) if len(logbook.location_samples) else []
        return render_template('logbook/view.html', logbook=logbook, googlemapskey=app.config['GOOGLE_MAPS_KEY'],
                               waypoints_idx=waypoints_idx)


@app.route('/driverslogbook/create', methods=['POST'])
@expects_json({
    'type': 'object',
    'properties': {
        'title': {'type': 'string'},
        'rideType': {'type': 'string', "enum": list(map(lambda c: c.name, data_models.RideType))}
    },
    'required': ['title', 'rideType']
})
@authentication_required
def create_driverslogbook(current_user: AdminUser):
    data = g.data
    app.logger.info("Create Logbook")
    app.logger.debug("Request=({})".format(data))

    with app.app_context():
        ride_type = data_models.RideType[data['rideType'].upper()]
        logbook = data_models.Logbook(title=data['title'], ride_type=ride_type, status=data_models.RideStatus.RUNNING)
        db.session.add(logbook)
        db.session.commit()
        return jsonify({'error': False, 'logbookData': {"logbookID": logbook.id}}), 200

    return jsonify({'error': True, 'errorMessage': 'Unable to create logbook.'}), 500


@app.route('/driverslogbook/complete', methods=['POST'])
@expects_json({})
@authentication_required
def complete_all_driverslogbooks(current_user: AdminUser):
    app.logger.info("Complete all logbooks")

    with app.app_context():
        logbooks = db.session.query(data_models.Logbook).filter(data_models.Logbook.status == data_models.RideStatus.RUNNING)

        for logbook in logbooks:
            logbook.status = data_models.RideStatus.COMPLETE
            db.session.add(logbook)

        db.session.commit()
        return jsonify({'error': False}), 200

    return jsonify({'error': True, 'errorMessage': 'Unable to complete all running logbooks.'}), 500


@app.route('/driverslogbook/<int:logbook_id>/complete', methods=['POST'])
@expects_json({})
@authentication_required
def complete_driverslogbook(current_user: AdminUser, logbook_id=0):
    app.logger.info("Complete Logbook")

    with app.app_context():
        logbook = db.session.query(data_models.Logbook).filter(data_models.Logbook.id == logbook_id).first()

        if logbook is None:
            return jsonify({'error': True, 'errorMessage': 'Logbook #{} does not exist.'.format(logbook_id)}), 404

        logbook.status = data_models.RideStatus.COMPLETE
        db.session.add(logbook)
        db.session.commit()
        return jsonify({'error': False}), 200

    return jsonify({'error': True, 'errorMessage': 'Unable to complete logbook.'}), 500


@app.route('/driverslogbook/<int:logbook_id>/locationsample/create', methods=['POST'])
@expects_json({
    'type': 'object',
    'properties': {
        'longitude': {'type': 'number', 'minimum': -180, 'maximum': 180},
        'latitude': {'type': 'number', 'minimum': -90, 'maximum': 90}},
    'required': ['logbookId', 'longitude', 'latitude']
})
@authentication_required
def create_location_sample(current_user: AdminUser, logbook_id=0):
    data = request.json
    app.logger.info("Create Location Sample")
    app.logger.debug("Request=({})".format(data))

    with app.app_context():
        logbook = db.session.query(data_models.Logbook).filter(data_models.Logbook.id == logbook_id).first()

        if logbook is None:
            return jsonify({'error': True, 'errorMessage': 'Logbook #{} does not exist.'.format(logbook_id)})

        if logbook.status != data_models.RideStatus.RUNNING:
            return jsonify({'error': True, 'errorMessage': 'Logbook #{} is inactive.'.format(logbook_id)})

        location_sample = data_models.LocationSample(longitude=data['longitude'], latitude=data['latitude'],
                                                     logbook_id=logbook_id)
        db.session.add(location_sample)
        db.session.commit()
        return jsonify({'error': False, 'locationSample': {"locationSampleID": location_sample.id}}), 200

    return jsonify({'error': True, 'errorMessage': 'Unable to create location sample.'}), 500


@app.route('/prices')
@expects_json({})
def prices():
    if 'result' in PRICE_CACHE:
       return PRICE_CACHE['result']

    r = requests.get("https://www.onvista.de/index/S-P-500-Index-4359526")
    soup = BeautifulSoup(r.content, 'html.parser')
    selected_div = soup.findAll("span", {"data-push": "4359526:last:2:1:Index"})
    spx = selected_div[0].get_text().strip()
    selected_li = soup.findAll("li", {"data-push": "4359526:performanceRelative:2:1:Index"})
    spx_rel = selected_li[-1].get_text().strip()

    r = requests.get("https://www.onvista.de/index/NASDAQ-100-Index-325104")
    soup = BeautifulSoup(r.content, 'html.parser')
    selected_div = soup.findAll("span", {"data-push": "325104:last:2:1:Index"})
    nas = selected_div[0].get_text().strip()
    selected_li = soup.findAll("li", {"data-push": "325104:performanceRelative:2:1:Index"})
    nas_rel = selected_li[-1].get_text().strip()

    r = requests.get("https://www.onvista.de/index/DAX-Index-20735")
    soup = BeautifulSoup(r.content, 'html.parser')
    selected_div = soup.findAll("span", {"data-push": "20735:last:2:1:Index"})
    dax = selected_div[0].get_text().strip()
    selected_li = soup.findAll("li", {"data-push": "20735:performanceRelative:2:1:Index"})
    dax_rel = selected_li[-1].get_text().strip()

    result = {'s&p500': spx_rel, 'nasdaq100': nas_rel, 'dax': dax_rel}
    PRICE_CACHE['result'] = result
    return result


def create_app():
    CORS(app)
    app.secret_key = app.config['SECRET_KEY']
    #helper.setup_logging(app, logging.INFO, paths_and_line_numbers=False)
    #helper.init_config(app)

    with app.app_context():
        data_models.db.create_all()
        data_models.db.session.commit()
        create_and_add_admin_users_to_database(app.config)

    admin = Admin(app, name='Logbook', template_mode='bootstrap3')
    admin.add_view(data_models.StandardModelView(data_models.Logbook, data_models.db.session))
    admin.add_view(data_models.StandardModelView(data_models.LocationSample, data_models.db.session))

    app.register_blueprint(auth_blueprint)
    return app


def main():
    flask_app = create_app()
    if app_settings.endswith("ProductionConfig"):
        flask_app.run(host='0.0.0.0', port=9002, debug=False)
    else:
        flask_app.run(host='0.0.0.0', port=9002, debug=True)


if __name__ == '__main__':
    main()
