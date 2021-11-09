import os
from config import basedir
from flask_restful import Resource, reqparse, abort, fields, marshal_with
from app import db, api
from app.models import Banner, User
from flask_httpauth import HTTPBasicAuth


auth = HTTPBasicAuth()

resource_fields = {
    # 'id': fields.Integer,
    'title': fields.String,
    'image': fields.String,
    'user_id': fields.Integer,
    'uri': fields.Url()
}

parser = reqparse.RequestParser()
parser.add_argument('id', type=int, help='Id of the banner to update.')
parser.add_argument('title', type=str, help='Title for the banner.')


@auth.verify_password
def verify(username, password):
    if not (username and password):
        return False
    user = User.query.filter_by(username=username).first()
    if not user:
        return False
    return user.check_password(password)

class BannerApi(Resource):
    decorators = [auth.login_required]

    @marshal_with(resource_fields)
    def get(self, id=None):
        if id:
            banners = Banner.query.filter_by(id=id).first()
        else:
            banners = Banner.query.all()
        return banners

    @marshal_with(resource_fields)
    def put(self):
        args = parser.parse_args()
        args['title']
        banner = Banner.query.filter_by(id=args['id']).first()
        if not banner:
            abort(404, message='Banner does not exist.')
        banner.title = args['title']
        db.session.commit()
        return banner

    @marshal_with(resource_fields)
    def delete(self):
        args = parser.parse_args()
        banner = Banner.query.filter_by(id=args['id']).first()
        if not banner:
            abort(404, message='Banner does not exist.')
        try:
            os.unlink(os.path.join(basedir, 'app/static/banners', banner.image))
            os.unlink(os.path.join(basedir, 'app/static/banners/thumbnail', banner.image))
            db.session.delete(banner)
            db.session.commit()
        except Exception as e:
            print(e)
        return banner

api.add_resource(BannerApi, '/api/banner', '/api/banner/<int:id>', endpoint="banner-api")
# api.add_resource(BannerApi, '/api/banner/<int:id>', endpoint='id')
