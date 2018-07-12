import React, {Component} from 'react';
import {Redirect} from 'react-router-dom'
import PropTypes from 'prop-types';

import AuthController from '../../../util/AuthController';
import {Button, FormGroup} from '@blueprintjs/core';

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
                <FormGroup label={'Username'} labelInfo={'(required)'}>
                    <input className="bp3-input" onChange={this.onUsernameChange} value={this.state.username}/>
                </FormGroup>
                <FormGroup label={'Email'} labelInfo={'(required)'}>
                    <input className="bp3-input" onChange={this.onEmailChange} value={this.state.email}/>
                </FormGroup>
                <FormGroup label={'Password'} labelInfo={'(required)'}>
                    <input className="bp3-input" onChange={this.onPasswordChange} value={this.state.password}/>
                </FormGroup>
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
