import React from 'react';
import PostHeader from './PostHeader/PostHeader'
import {store} from "../../data/store";
import {Button, Menu, MenuItem, NonIdealState, Popover, Position, TextArea} from '@blueprintjs/core';

import './Post.css'
import PostContent from "./PostContent/PostContent";
import {Link} from "react-router-dom";

class Post extends React.Component {
    constructor(props) {
        super(props);
        this.onChange = this.onChange.bind(this);
        this.state = {
            error: false,
            post: {}
        }
    }

    componentDidMount() {
        console.log(this.props.match.params.id);
        store.find('post', this.props.match.params.id).then(e => {
            this.setState({
                post: e
            });
            console.log(this.state);
        }).catch(e => {
            console.log(e);
            this.setState({
                error: true
            });
        });
    }

    onChange(e) {
        console.log(e);
        this.state.post.contents = e.target.value;
        this.setState({
            post: this.state.post
        });
    }

    render() {
        if (this.state.error) {
            return (
                <div>
                    <Popover content={<Menu> <MenuItem text="Submenu">
                        <MenuItem text="Child one"/>
                        <MenuItem text="Child two"/>
                        <MenuItem text="Child three"/>
                    </MenuItem></Menu>} position={Position.RIGHT_TOP}>
                        <Button icon="share" text="Open in..."/>
                    </Popover>
                    <NonIdealState className={"header"} title={"This post could not be loaded"}
                                   visual={"warning-sign"}
                                   description={"There was an error attempting to load this post."}
                                   action={<Link to={"/"}>Go home</Link>}/>
                </div>
            )
        }
        return (
            <div>
                <TextArea
                    large={true}
                    onChange={this.onChange}
                    value={this.state.post.contents}
                />
                <PostHeader className="header" title={this.state.post.title}/>
                <PostContent content={this.state.post.contents}/>
            </div>
        )
    }
}

export default Post;