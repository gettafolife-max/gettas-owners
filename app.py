import os
from datetime import datetime
from functools import wraps
from decimal import Decimal

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv(
    "SECRET_KEY",
    "change-this-secret-key-before-production"
)

database_url = os.getenv("DATABASE_URL", "sqlite:///owners.db")

if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://",
        "postgresql://",
        1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# =========================================================
# MODELS
# =========================================================


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(
        db.String(120),
        nullable=False
    )

    email = db.Column(
        db.String(180),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(30),
        nullable=False,
        default="owner"
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )

    units = db.relationship(
        "Unit",
        backref="owner",
        lazy=True
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(
            self.password_hash,
            password
        )


class Unit(db.Model):
    __tablename__ = "units"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    name = db.Column(
        db.String(120),
        nullable=False
    )

    building = db.Column(
        db.String(160),
        nullable=True
    )

    apartment_number = db.Column(
        db.String(50),
        nullable=True
    )

    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True
    )

    owner_share = db.Column(
        db.Numeric(5, 2),
        nullable=False,
        default=70
    )

    company_share = db.Column(
        db.Numeric(5, 2),
        nullable=False,
        default=30
    )

    currency = db.Column(
        db.String(10),
        nullable=False,
        default="GEL"
    )

    is_active = db.Column(
        db.Boolean,
        nullable=False,
        default=True
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )

    entries = db.relationship(
        "FinancialEntry",
        backref="unit",
        lazy=True,
        cascade="all, delete-orphan"
    )


class FinancialEntry(db.Model):
    __tablename__ = "financial_entries"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    unit_id = db.Column(
        db.Integer,
        db.ForeignKey("units.id"),
        nullable=False
    )

    entry_type = db.Column(
        db.String(20),
        nullable=False
    )

    category = db.Column(
        db.String(120),
        nullable=False
    )

    description = db.Column(
        db.String(255),
        nullable=True
    )

    amount = db.Column(
        db.Numeric(12, 2),
        nullable=False
    )

    date = db.Column(
        db.Date,
        nullable=False,
        default=datetime.utcnow
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )


# =========================================================
# HELPERS
# =========================================================


def decimal_value(value):
    if value is None:
        return Decimal("0")

    if isinstance(value, Decimal):
        return value

    return Decimal(str(value))


def money(value):
    value = decimal_value(value)
    return f"{value:,.2f}".replace(",", " ")


app.jinja_env.filters["money"] = money


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))

        if session.get("role") != "admin":
            abort(403)

        return view(*args, **kwargs)

    return wrapped_view


def current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    return db.session.get(User, user_id)


def get_unit_summary(unit, year=None, month=None):
    query = FinancialEntry.query.filter_by(
        unit_id=unit.id
    )

    if year:
        query = query.filter(
            db.extract(
                "year",
                FinancialEntry.date
            ) == year
        )

    if month:
        query = query.filter(
            db.extract(
                "month",
                FinancialEntry.date
            ) == month
        )

    entries = query.order_by(
        FinancialEntry.date.desc(),
        FinancialEntry.id.desc()
    ).all()

    total_income = sum(
        (
            decimal_value(entry.amount)
            for entry in entries
            if entry.entry_type == "income"
        ),
        Decimal("0")
    )

    total_expenses = sum(
        (
            decimal_value(entry.amount)
            for entry in entries
            if entry.entry_type == "expense"
        ),
        Decimal("0")
    )

    net_profit = total_income - total_expenses

    owner_share = (
        decimal_value(unit.owner_share)
        / Decimal("100")
    )

    company_share = (
        decimal_value(unit.company_share)
        / Decimal("100")
    )

    owner_profit = net_profit * owner_share
    company_profit = net_profit * company_share

    return {
        "entries": entries,
        "income": total_income,
        "expenses": total_expenses,
        "net_profit": net_profit,
        "owner_profit": owner_profit,
        "company_profit": company_profit,
    }


# =========================================================
# AUTH
# =========================================================


@app.route("/")
def index():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))

    return redirect(url_for("owner_dashboard"))


@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():
    if session.get("user_id"):
        return redirect(url_for("index"))

    if request.method == "POST":
        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        user = User.query.filter_by(
            email=email
        ).first()

        if not user:
            flash(
                "Неверный email или пароль.",
                "error"
            )

            return render_template(
                "login.html"
            )

        if not user.check_password(password):
            flash(
                "Неверный email или пароль.",
                "error"
            )

            return render_template(
                "login.html"
            )

        session.clear()

        session["user_id"] = user.id
        session["role"] = user.role
        session["name"] = user.name

        return redirect(url_for("index"))

    return render_template(
        "login.html"
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# =========================================================
# ADMIN
# =========================================================


@app.route("/admin")
@admin_required
def admin_dashboard():
    units = Unit.query.order_by(
        Unit.created_at.desc()
    ).all()

    total_income = Decimal("0")
    total_expenses = Decimal("0")
    total_owner_profit = Decimal("0")
    total_company_profit = Decimal("0")

    unit_cards = []

    for unit in units:
        summary = get_unit_summary(unit)

        total_income += summary["income"]
        total_expenses += summary["expenses"]
        total_owner_profit += summary["owner_profit"]
        total_company_profit += summary["company_profit"]

        unit_cards.append({
            "unit": unit,
            "summary": summary,
        })

    return render_template(
        "admin_dashboard.html",
        unit_cards=unit_cards,
        total_income=total_income,
        total_expenses=total_expenses,
        total_owner_profit=total_owner_profit,
        total_company_profit=total_company_profit,
    )


@app.route(
    "/admin/unit/create",
    methods=["POST"]
)
@admin_required
def create_unit():
    name = request.form.get(
        "name",
        ""
    ).strip()

    building = request.form.get(
        "building",
        ""
    ).strip()

    apartment_number = request.form.get(
        "apartment_number",
        ""
    ).strip()

    owner_name = request.form.get(
        "owner_name",
        ""
    ).strip()

    owner_email = request.form.get(
        "owner_email",
        ""
    ).strip().lower()

    owner_password = request.form.get(
        "owner_password",
        ""
    )

    currency = request.form.get(
        "currency",
        "GEL"
    ).strip().upper()

    try:
        owner_share = Decimal(
            request.form.get(
                "owner_share",
                "70"
            )
        )
    except Exception:
        owner_share = Decimal("70")

    if not name:
        flash(
            "Укажите название номера.",
            "error"
        )
        return redirect(
            url_for("admin_dashboard")
        )

    if owner_share < 0:
        owner_share = Decimal("0")

    if owner_share > 100:
        owner_share = Decimal("100")

    company_share = (
        Decimal("100")
        - owner_share
    )

    owner = None

    if owner_email:
        owner = User.query.filter_by(
            email=owner_email
        ).first()

        if not owner:
            if not owner_name:
                flash(
                    "Укажите имя собственника.",
                    "error"
                )

                return redirect(
                    url_for(
                        "admin_dashboard"
                    )
                )

            if not owner_password:
                flash(
                    "Укажите пароль для собственника.",
                    "error"
                )

                return redirect(
                    url_for(
                        "admin_dashboard"
                    )
                )

            owner = User(
                name=owner_name,
                email=owner_email,
                role="owner",
            )

            owner.set_password(
                owner_password
            )

            db.session.add(owner)
            db.session.flush()

    unit = Unit(
        name=name,
        building=building,
        apartment_number=apartment_number,
        owner_id=(
            owner.id
            if owner
            else None
        ),
        owner_share=owner_share,
        company_share=company_share,
        currency=currency,
    )

    db.session.add(unit)
    db.session.commit()

    flash(
        "Номер добавлен.",
        "success"
    )

    return redirect(
        url_for(
            "admin_unit",
            unit_id=unit.id
        )
    )


@app.route("/admin/unit/<int:unit_id>")
@admin_required
def admin_unit(unit_id):
    unit = db.session.get(
        Unit,
        unit_id
    )

    if not unit:
        abort(404)

    year = request.args.get(
        "year",
        type=int
    )

    month = request.args.get(
        "month",
        type=int
    )

    summary = get_unit_summary(
        unit,
        year=year,
        month=month
    )

    return render_template(
        "unit.html",
        unit=unit,
        summary=summary,
        selected_year=year,
        selected_month=month,
    )


@app.route(
    "/admin/unit/<int:unit_id>/entry",
    methods=["POST"]
)
@admin_required
def add_entry(unit_id):
    unit = db.session.get(
        Unit,
        unit_id
    )

    if not unit:
        abort(404)

    entry_type = request.form.get(
        "entry_type"
    )

    category = request.form.get(
        "category",
        ""
    ).strip()

    description = request.form.get(
        "description",
        ""
    ).strip()

    amount_raw = request.form.get(
        "amount",
        "0"
    )

    date_raw = request.form.get(
        "date"
    )

    if entry_type not in {
        "income",
        "expense"
    }:
        flash(
            "Некорректный тип операции.",
            "error"
        )

        return redirect(
            url_for(
                "admin_unit",
                unit_id=unit.id
            )
        )

    if not category:
        flash(
            "Укажите категорию.",
            "error"
        )

        return redirect(
            url_for(
                "admin_unit",
                unit_id=unit.id
            )
        )

    try:
        amount = Decimal(
            amount_raw
        )
    except Exception:
        flash(
            "Некорректная сумма.",
            "error"
        )

        return redirect(
            url_for(
                "admin_unit",
                unit_id=unit.id
            )
        )

    if amount <= 0:
        flash(
            "Сумма должна быть больше нуля.",
            "error"
        )

        return redirect(
            url_for(
                "admin_unit",
                unit_id=unit.id
            )
        )

    try:
        entry_date = datetime.strptime(
            date_raw,
            "%Y-%m-%d"
        ).date()
    except Exception:
        entry_date = datetime.utcnow().date()

    entry = FinancialEntry(
        unit_id=unit.id,
        entry_type=entry_type,
        category=category,
        description=description,
        amount=amount,
        date=entry_date,
    )

    db.session.add(entry)
    db.session.commit()

    flash(
        "Операция добавлена.",
        "success"
    )

    return redirect(
        url_for(
            "admin_unit",
            unit_id=unit.id
        )
    )


@app.route(
    "/admin/entry/<int:entry_id>/delete",
    methods=["POST"]
)
@admin_required
def delete_entry(entry_id):
    entry = db.session.get(
        FinancialEntry,
        entry_id
    )

    if not entry:
        abort(404)

    unit_id = entry.unit_id

    db.session.delete(entry)
    db.session.commit()

    flash(
        "Операция удалена.",
        "success"
    )

    return redirect(
        url_for(
            "admin_unit",
            unit_id=unit_id
        )
    )


# =========================================================
# OWNER
# =========================================================


@app.route("/owner")
@login_required
def owner_dashboard():
    user = current_user()

    if not user:
        return redirect(
            url_for("login")
        )

    if user.role == "admin":
        return redirect(
            url_for(
                "admin_dashboard"
            )
        )

    units = Unit.query.filter_by(
        owner_id=user.id,
        is_active=True
    ).order_by(
        Unit.created_at.desc()
    ).all()

    unit_cards = []

    total_income = Decimal("0")
    total_expenses = Decimal("0")
    total_owner_profit = Decimal("0")

    for unit in units:
        summary = get_unit_summary(unit)

        unit_cards.append({
            "unit": unit,
            "summary": summary,
        })

        total_income += summary["income"]
        total_expenses += summary["expenses"]
        total_owner_profit += summary["owner_profit"]

    return render_template(
        "owner_dashboard.html",
        user=user,
        unit_cards=unit_cards,
        total_income=total_income,
        total_expenses=total_expenses,
        total_owner_profit=total_owner_profit,
    )


@app.route(
    "/owner/unit/<int:unit_id>"
)
@login_required
def owner_unit(unit_id):
    user = current_user()

    if not user:
        return redirect(
            url_for("login")
        )

    unit = db.session.get(
        Unit,
        unit_id
    )

    if not unit:
        abort(404)

    if (
        user.role != "admin"
        and unit.owner_id != user.id
    ):
        abort(403)

    year = request.args.get(
        "year",
        type=int
    )

    month = request.args.get(
        "month",
        type=int
    )

    summary = get_unit_summary(
        unit,
        year=year,
        month=month
    )

    return render_template(
        "owner_unit.html",
        unit=unit,
        summary=summary,
        selected_year=year,
        selected_month=month,
    )


# =========================================================
# INITIAL DATABASE
# =========================================================


def create_default_admin():
    admin_email = os.getenv(
        "ADMIN_EMAIL",
        "admin@gettas.ge"
    ).lower()

    admin_password = os.getenv(
        "ADMIN_PASSWORD",
        "admin123"
    )

    existing_admin = User.query.filter_by(
        email=admin_email
    ).first()

    if existing_admin:
        return

    admin = User(
        name="Getta's Management",
        email=admin_email,
        role="admin",
    )

    admin.set_password(
        admin_password
    )

    db.session.add(admin)
    db.session.commit()


with app.app_context():
    db.create_all()
    create_default_admin()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv(
                "PORT",
                5000
            )
        ),
        debug=os.getenv(
            "FLASK_DEBUG"
        ) == "1",
    )
