import io
import os
import numpy as np
from PIL import Image, ImageOps
from datetime import datetime
from random import shuffle
from config import basedir
import secrets
from app import app, db
from flask.json import jsonify
from flask import render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from app.forms import BannerForm, LoginForm, RegisterForm
from app.models import Banner, User
import cv2
import boto3

BUCKET_NAME='bannerapp'


''' saves an image with centralize crop.
def center_crop(form_image, dim):
    rtx = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_image.filename)
    if f_ext in ['.jpg', '.png', '.jpeg']:
        filename = rtx + f_ext
        picture_path = os.path.join(app.root_path, 'static/banners', filename)

        in_memory_file = io.BytesIO()
        val = form_image.save(in_memory_file)
        print('val: ', val)
        data = np.fromstring(in_memory_file.getvalue(), dtype=np.uint8)
        color_image_flag = 1
        img = cv2.imdecode(data, color_image_flag)
        width, height = img.shape[1], img.shape[0]
        #process crop width and height for max available dimension
        crop_width = dim[0] if dim[0]<img.shape[1] else img.shape[1]
        crop_height = dim[1] if dim[1]<img.shape[0] else img.shape[0] 
        mid_x, mid_y = int(width/2), int(height/2)
        cw2, ch2 = int(crop_width/2), int(crop_height/2) 
        crop_img = img[mid_y-ch2:mid_y+ch2, mid_x-cw2:mid_x+cw2]
        cv2.imwrite(picture_path, crop_img)

        imageName = str(datetime.now().strftime("%Y_%m_%d_%H_%M_%S")) + '.jpg'

        image_string = cv2.imencode(f_ext, crop_img)[1].tostring()
        s3.put_object(Bucket="banner-app", Key=imageName, Body=image_string)

        return filename
    else:
        flash(f'{form_image.filename} was not able to upload. {f_ext} files are not supported', 'danger')
        return None
'''


def save_image(file):
    '''saves images with a thumbnail of size 125*100. and uploads the original image to aws s3 bucket.'''

    rtx = secrets.token_hex(8)
    _, f_ext = os.path.splitext(file.filename)
    if f_ext in ['.jpg', '.png', '.jpeg']:
        filename = rtx + f_ext
        picture_path = os.path.join(app.root_path, 'static/banners', filename)
        file.save(picture_path)
        picture_path_thumb_dir = os.path.join(app.root_path, 'static/banners/thumbnail')
        picture_path_thumb = os.path.join(app.root_path, 'static/banners/thumbnail', filename)
        if not os.path.exists(picture_path_thumb_dir):
            os.makedirs(picture_path_thumb_dir)

        thumb_size = (125, 100)
        i = Image.open(file)
        i.thumbnail(thumb_size, Image.NEAREST)
        thumb = ImageOps.fit(i, thumb_size, Image.ANTIALIAS)
        thumb.save(picture_path_thumb)
        # s3.upload_file(
        #             Bucket = BUCKET_NAME,
        #             Filename=picture_path,
        #             Key = filename
        #         )

        return filename


@app.route('/', methods=['GET','POST'])
@app.route('/<int:page>', methods=['GET','POST'])
@app.route('/home', methods=['GET','POST'])
@app.route('/home/<int:page>', methods=['GET','POST'])
@login_required
def index(page=1):
    form = BannerForm()
    if form.validate_on_submit():

        for file in form.image.data:
            try:
                # filename = center_crop(file, (1000, 1000))
                filename = save_image(file)
                if filename:
                    banner = Banner(title=form.title.data, image=filename, user_id=current_user.id)
                    db.session.add(banner)
            except Exception as e:
                print(e)
                flash(f'{file.filename} was not able to upload.', 'danger')

        db.session.commit()

        flash('All files were uploaded!', 'success')
        redirect(url_for('index'))

    # banners = Banner.query.order_by(func.random()).paginate(page, 12, False)
    banners = Banner.query.offset(0).limit(12).all()
    shuffle(banners)

    return render_template('index.html', title='Home', form=form, pages=banners)


@app.route('/show_more_banner/<int:offset>')
def show_more_banner(offset):

    banners = Banner.query.offset(offset).limit(12).all()
    shuffle(banners)
    if not banners:
        return '0'
    return render_template('loaddata.html', banners=banners)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first_or_404()
        if not user or not user.check_password(form.password.data):
            flash('Email or password is incorrect. Please try again.')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('index'))
    return render_template('login.html', title='Login', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegisterForm()

    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', title='Register', form=form)
    

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/profile')
def user():
    pass
