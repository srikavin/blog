import React, {Component} from 'react';
import {Redirect} from 'react-router-dom'
import PropTypes from 'prop-types';
import Login from './Login/Login';
import {Callout, Intent, Spinner, Tab, Tabs} from '@blueprintjs/core';

import './Auth.css'
import Register from "./Register/Register";

class Auth extends Component {
    constructor(props) {
        super(props);
        this.onSuccess = this.onSuccess.bind(this);
        this.onError = this.onError.bind(this);
        this.onSubmit = this.onSubmit.bind(this);
        this.onTabChange = this.onTabChange.bind(this);
        this.state = {
            redirectToReferrer: false,
            loading: false,
            error: false,
            timeout: -1,
            selectedTab: 'Login'
        };
    }

    onTabChange(newTab) {
        this.setState({selectedTab: newTab});
    };

    onSuccess(res) {
        this.setState({
            redirectToReferrer: true,
            loading: false
        });
    }

    onError() {
        clearTimeout(this.state.timeout);
        let timeout = setTimeout(() => {
            this.setState({error: false});
        }, 5000);
        this.setState({
            error: true,
            loading: false,
            timeout: timeout
        });
    }

    onSubmit() {
        this.setState({
            loading: true
        });
    }

    handleError() {
        if (this.state.error) {
            return (
                <Callout className={"errorAlert"} intent={Intent.DANGER} title={"Invalid Login"}>
                    An incorrect username or password was entered.
                </Callout>
            );
        }
    }

    render() {
        const {from} = this.props.from || {from: {pathname: "/post"}};

        console.log(this.state);

        if (this.state.redirectToReferrer) {
            return (
                <Redirect to={from}/>
            )
        }

        if (this.state.loading) {
            return (
                <div className={"container"}>
                    <div className={"authContainer"}>
                        <div className={"authTabs"}>
                            <Spinner large/>
                        </div>
                    </div>
                </div>
            );
        }

        return (
            <div className={"container"}>
                {this.handleError()}
                <div className={"authContainer"}>
                    <Tabs id={"AuthSelect"} className={"authTabs"}
                          onChange={this.onTabChange} selectedTabId={this.state.selectedTab}>

                        <Tab id={"Login"} title={"Login"} panel={
                            <Login callback={this.onSuccess} onError={this.onError} onSubmit={this.onSubmit}/>
                        }/>
                        <Tab id={"Register"} title={"Register"} panel={
                            <Register callback={this.onSuccess} onError={this.onError} onSubmit={this.onSubmit}/>
                        }/>
                    </Tabs>
                </div>
            </div>
        )
    }
}

Auth.propTypes = {
    from: PropTypes.string
};

export default Auth;