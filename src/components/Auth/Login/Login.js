import React, {Component} from 'react';
import {Redirect} from 'react-router-dom'
import PropTypes from 'prop-types';
import {Button, Label} from '@blueprintjs/core'

import AuthController from '../../../util/AuthController';

class Login extends Component {
    constructor(props) {
        super(props);
        this.auth = AuthController.getInstance();
        this.state = {
            redirectToReferrer: false,
            email: "",
            password: "",
        };
        this.onEmailChange = this.onEmailChange.bind(this);
        this.onPasswordChange = this.onPasswordChange.bind(this);
        this.onSubmit = this.onSubmit.bind(this);
    }

    onEmailChange(event) {
        this.setState({
            email: event.target.value
        });
    }

    onPasswordChange(event) {
        this.setState({
            password: event.target.value
        });
    }

    onSubmit(event) {
        this.props.onSubmit();
        event.preventDefault();
        this.auth.login(this.state.email, this.state.password)
            .then(res => this.props.callback(res))
            .catch(this.props.onError);
    }

    render() {
        const {from} = this.props.from || {from: {pathname: "/me"}};

        if (this.state.redirectToReferrer) {
            return (
                <Redirect to={from}/>
            )
        }

        return (
            <form onSubmit={this.onSubmit}>
                <Label text={"Email"} helperText={"(required)"}>
                    <input className="pt-input" onChange={this.onEmailChange} value={this.state.email}/>
                </Label>
                <Label text={"Password"} helperText={"(required)"}>
                    <input className="pt-input" onChange={this.onPasswordChange} value={this.state.password}/>
                </Label>
                <Button text="Login" type="submit"/>
            </form>
        )
    }
}

Login.propTypes = {
    callback: PropTypes.func.isRequired,
    onError: PropTypes.func,
    onSubmit: PropTypes.func
};

export default Login;
