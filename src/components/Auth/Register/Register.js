import React, {Component} from 'react';
import {Redirect} from 'react-router-dom'
import PropTypes from 'prop-types';

import AuthController from '../../../util/AuthController';
import {Button, Label} from "@blueprintjs/core";

class Register extends Component {
    constructor(props) {
        super(props);
        this.auth = AuthController.getInstance();
        this.onEmailChange = this.onEmailChange.bind(this);
        this.onPasswordChange = this.onPasswordChange.bind(this);
        this.onUsernameChange = this.onUsernameChange.bind(this);
        this.onSubmit = this.onSubmit.bind(this);
        this.state = {
            email: "",
            password: "",
            username: ""
        }
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

    onUsernameChange(event) {
        this.setState({
            username: event.target.value
        });
    }

    onSubmit(event) {
        this.props.onSubmit();
        event.preventDefault();
        this.auth.register(this.state.username, this.state.email, this.state.password)
            .then(res => this.props.callback(res))
            .catch(this.props.onError);
    }

    render() {
        const {from} = this.props.from || {from: {pathname: "/post"}};

        if (this.state.redirectToReferrer) {
            return (
                <Redirect to={from}/>
            )
        }

        return (
            <form onSubmit={this.onSubmit}>
                <Label text={"Username"} helperText={"(required)"}>
                    <input className="pt-input" onChange={this.onUsernameChange} value={this.state.username}/>
                </Label>
                <Label text={"Email"} helperText={"(required)"}>
                    <input className="pt-input" onChange={this.onEmailChange} value={this.state.email}/>
                </Label>
                <Label text={"Password"} helperText={"(required)"}>
                    <input className="pt-input" onChange={this.onPasswordChange} value={this.state.password}/>
                </Label>
                <Button text="Register" type="submit"/>
            </form>
        )
    }
}

Register.propTypes = {
    callback: PropTypes.func.isRequired,
    onError: PropTypes.func,
    onSubmit: PropTypes.func
};

export default Register;
