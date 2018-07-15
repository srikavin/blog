import React, {Component} from 'react';
import {Redirect} from 'react-router-dom'
import PropTypes from 'prop-types';
import {Button, FormGroup} from '@blueprintjs/core'

import {Auth} from '../../../data/resource/auth';

class Login extends Component {
    constructor(props) {
        super(props);
        this.state = {
            redirectToReferrer: false,
            email: '',
            password: ''
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
        Auth.login(this.state.email, this.state.password)
            .then(res => this.props.callback(res))
            .catch(this.props.onError);
    }

    render() {
        const {from} = this.props.from || {from: {pathname: '/me'}};

        if (this.state.redirectToReferrer) {
            return (
                <Redirect to={from}/>
            )
        }

        return (
            <form onSubmit={this.onSubmit}>
                <FormGroup label={'Email'} labelInfo={'(required)'}>
                    <input className="bp3-input" onChange={this.onEmailChange} value={this.state.email}/>
                </FormGroup>
                <FormGroup label={'Password'} labelInfo={'(required)'}>
                    <input className="bp3-input" onChange={this.onPasswordChange} value={this.state.password}/>
                </FormGroup>
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
